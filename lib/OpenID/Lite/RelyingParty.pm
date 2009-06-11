package OpenID::Lite::RelyingParty;

use Any::Moose;

use OpenID::Lite::Identifier;
use OpenID::Lite::Message;
use OpenID::Lite::RelyingParty::Discover;
use OpenID::Lite::RelyingParty::Associator;
use OpenID::Lite::RelyingParty::CheckID::Request;

use OpenID::Lite::RelyingParty::IDResHandler;
use OpenID::Lite::RelyingParty::Store::OnMemory;

use URI;
use Params::Validate;

has '_discoverer' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_associator' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_id_res_handler' => (
    is         => 'ro',
    lazy_build => 1,
);

has 'session' => (
    is  => 'rw',
    isa => 'HTTP::Session',
);

has 'store' => (
    is      => 'rw',
    does    => 'OpenID::Lite::Role::Storable',
    default => sub { OpenID::Lite::RelyingParty::Store::OnMemory->new },
);

with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::Associator';
with 'OpenID::Lite::Role::Discoverer';

sub begin {
    my ( $self, $user_suplied_identifier, $anonymous ) = @_;

    my $identifier = $self->normalize_identifier($user_suplied_identifier);
    return unless $identifier;

    my $services = $self->discover($identifier);
    return unless $services;

    my $service = $services->[0];

    $self->begin_without_discovery( $service, $anonymous );
}

sub begin_without_discovery {
    my ( $self, $service, $anonymous ) = @_;

    my $association = $self->associate($service) or return;

    #return unless $association;

    my %params = ( service => $service );
    $params{association} = $association if $association;
    $params{anonymous}   = 1            if $anonymous;

    my $checkid_req
        = OpenID::Lite::RelyingParty::CheckID::Request->new(%params);
    $self->last_requested_endpoint($service);

    return $checkid_req;
}

sub last_requested_endpoint {
    my ( $self, $endpoint ) = @_;
    return unless $self->session;
    if ($endpoint) {
        $self->session->set( 'openid.last_requested_endpoint', $endpoint );
    }
    else {
        $endpoint = $self->session->get('openid.last_requested_endpoint');
    }
    return $endpoint;
}

sub normalize_identifier {
    my ( $self, $user_suplied_identifier ) = @_;
    my $identifier
        = OpenID::Lite::Identifier->normalize($user_suplied_identifier);
    return $identifier
        ? $identifier
        : $self->ERROR( sprintf q{Invalid identifier: %s},
        $user_suplied_identifier );
}

sub discover {
    my ( $self, $identifier ) = @_;

    # execute discovery
    my $services = $self->_discoverer->discover($identifier)
        or return $self->ERROR( $self->_discoverer->errstr );
    return $self->ERROR( sprintf q{Service not found for identifier %s},
        $identifier )
        unless @$services > 0;

    # pick up op-identifier information if it exists
    my @op_identifiers = grep { $_->is_op_identifier } @$services;
    return \@op_identifiers if @op_identifiers > 0;

    # sorted by priority
    # we like 2.0 service endpoint rather than 1.X.
    my @sorted_services
        = sort { $a->type_priority <=> $b->type_priority } @$services;

    return \@sorted_services;
}

sub associate {
    my ( $self, $service ) = @_;
    my $server_url = $service->url;

    # find association related to passed server-url
    my $association = $self->store->get_association($server_url);

    # if there isn't available association,
    # it starts to negotiate with provider to obtain new association.
    if ( !$association || $association->is_expired ) {
        $association = $self->_associator->associate($service)
            or return $self->ERROR( $self->_associator->errstr );

        # if it finished successfully, save it.
        $self->store->store_association( $server_url => $association )
            if $association;
    }
    return $association;
}

sub complete {
    my ( $self, $request, $current_url ) = @_;
    my $params  = OpenID::Lite::Message->from_request($request);
    my $service = $self->last_requested_endpoint;
    my %args    = (
        current_url => $current_url,
        params      => $params,
    );
    $args{service} = $service if $service;
    my $result = $self->idres(%args);
    return $result;
}

sub idres {
    my $self = shift;
    my %args = Params::Validate::validate(
        @_,
        {   current_url => 1,
            params      => {
                isa => 'OpenID::Lite::Message',
            },
            service     => {
                isa      => 'OpenID::Lite::RelyingParty::Discover::Service',
                optional => 1
            },
        }
    );
    return $self->_id_res_handler->idres(%args)
        || $self->ERROR( $self->_id_res_handler->errstr );
}

sub _build__discoverer {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover->new( agent => $self->agent,
    );
}

sub _build__associator {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Associator->new(
        agent        => $self->agent,
        assoc_type   => $self->assoc_type,
        session_type => $self->session_type,
    );
}

sub _build__id_res_handler {
    my $self = shift;
    return OpenID::Lite::RelyingParty::IDResHandler->new(
        agent => $self->agent,
        store => $self->store,
    );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME

OpenID::Lite::RelyingParty - openid client for relying party

=head1 SYNOPSIS

    sub login {

        my $self = shift;

        my $user_suplied_identifier = $self->req->param('openid_identifier');

        my $openid = OpenID::Lite::RelyingParty->new;
        my $checkid_request = $openid->begin( $user_suplied_identifier );

        my $sreg = OpenID::Lite::Extension::SREG::Request->new;
        $sreg->request_fields(qw(nickname));
        $checkid_request->add_extension($sreg);

        my $redirect_url = $checkid_request->redirect_url(
            return_to => q{http://example.com/return_to},
            realm     => q{http://example.com/},
            immediate => 1,
        );
        return $self->redirect_to( $redirect_url );
    }

    sub return_to {
        my $self = shift;
        my $openid = OpenID::Lite::RelyingParty->new;

        # XXX: fix me
        my $result = $openid->complete( $self->request, q{http://myapp/return_to} );
        if ( $result->is_success ) {

        } elsif ( $result->is_canceled ) {

        } elsif ( $result->is_needed_setup ) {

        } elsif ( $result->is_not_openid ) {

        } elsif ( $result->is_invalid ) {

        } elsif ( $result->is_error ) {

        }
    }

=head1 DESCRIPTION

=head1 METHODS

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
