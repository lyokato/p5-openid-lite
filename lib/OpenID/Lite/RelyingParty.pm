package OpenID::Lite::RelyingParty;

use Any::Moose;

use OpenID::Lite::Identifier;
use OpenID::Lite::Message;
use OpenID::Lite::RelyingParty::Discover;
use OpenID::Lite::RelyingParty::Associator;
use OpenID::Lite::RelyingParty::CheckIDRequest;

#use OpenID::Lite::RelyingParty::IDResHandler;
use OpenID::Lite::RelyingParty::Store::OnMemory;

use Data::Util qw(:check);
use URI;
use Params::Validate qw(HASHREF);

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

    # TODO: cache control
    my $identifier = $self->normalize_identifier($user_suplied_identifier)
        or return;
    my $services = $self->discover($identifier)
        or return;

    # TODO: cache service?
    # TODO: pick up proper one from discovered services
    my $service = $services->[0];

    $self->begin_without_discovery( $service, $anonymous );
}

sub begin_without_discovery {
    my ( $self, $service, $anonymous ) = @_;
    my $association = $self->associate($service)
        or return;    # or do checkid request with stateless mode?
    my $checkid_req = OpenID::Lite::RelyingParty::CheckIDRequest->new(
        service     => $service,
        association => $association,
        anonymous   => ( $anonymous ? 1 : 0 ),
    );
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
    my $self     = shift;
    my $services = $self->_discoverer->discover(@_)
        or return $self->ERROR( $self->_discoverer->errstr );

    my @op_identifiers = grep { $_->is_op_identifier } @$services;
    return \@op_identifiers if @op_identifiers > 0;

    my @sorted_services
        = sort { $a->type_priority <=> $b->type_priority } @$services;
    return \@sorted_services;
}

sub associate {
    my ( $self, $service ) = @_;
    my $server_url = $service->url;
    my $association
        = $self->store->get_association($server_url);
    if ( !$association || $association->is_expired ) {
        $association = $self->_associator->associate($service)
            or return $self->ERROR( $self->_associator->errstr );
        $self->store->store_association( $server_url => $association )
            if $association;
    }
    return $association;
}

sub complete {
    my ( $self, $current_url, $query_params ) = @_;
    my $params      = OpenID::Lite::Message->from_request($query_params);
    my $service     = $self->last_requested_endpoint;
    my $handle      = $params->get('assoc_handle');
    my $association = $self->store->get_association($service, $handle);
    my %args        = (
        current_url => $current_url,
        params      => $params,
    );
    $args{service}     = $service     if $service;
    $args{association} = $association if $association;
    my $result = $self->idres(%args);
    return $result;
}

sub idres {
    my $self = shift;
    my %args = Params::Validate::validate(
        @_,
        {   current_url => 1,
            params      => { type => HASHREF },
            service     => {
                isa      => 'OpenID::Lite::RelyingParty::Discover::Service',
                optional => 1
            },
            association => {
                isa      => 'OpenID::Lite::Association',
                optional => 1
            },
        }
    );
    $self->_id_res_handler->idres(%args)
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

    #    return OpenID::Lite::RelyingParty::IDResHandler->new(
    #        agent => $self->agent, );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME 

OpenID::Lite::RelyingParty - relying party clinet

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
        my $params = $self->request->params;

        # XXX: fix me
        my $result = $openid->complete( q{http://myapp/return_to}, $params );
        if ( $result->is_success ) {

        } elsif ( $result->is_canceled ) {

        } elsif ( $result->is_needed_setup ) {

        } else {

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
