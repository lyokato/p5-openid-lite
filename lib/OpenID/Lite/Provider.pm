package OpenID::Lite::Provider;

use Any::Moose;
use OpenID::Lite::Message;
use OpenID::Lite::Realm;
use OpenID::Lite::Provider::Discover;
use OpenID::Lite::Provider::Response;
use OpenID::Lite::Provider::AssociationBuilder;
use OpenID::Lite::Provider::Handler::Association;
use OpenID::Lite::Provider::Handler::CheckAuth;
use OpenID::Lite::Provider::Handler::CheckID;
use OpenID::Lite::Constants::ModeType qw(:all);
use OpenID::Lite::Constants::Namespace qw(:all);
use OpenID::Lite::Constants::ProviderResponseType qw(:all);

with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';

has 'secret_lifetime' => (
    is      => 'rw',
    isa     => 'Int',
    default => 14 * 24 * 60 * 60,
);

has 'server_secret' => (
    is      => 'ro',
    isa     => 'Str',
    default => q{secret},
);

has 'secret_gen_interval' => (
    is      => 'rw',
    isa     => 'Int',
    default => 14 * 24 * 60 * 60,
);

has 'get_server_secret' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return ''; }
    },
);

has 'setup_url' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'endpoint_url' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'get_user' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return; }
    },
);

has 'get_identity' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return; }
    },
);

has 'is_identity' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return; }
    },
);

has 'is_trusted' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return; }
    },
);

has '_discoverer' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::Provider::Discover',
    lazy_build => 1,
);

has '_assoc_builder' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::Provider::AssociationBuilder',
    lazy_build => 1,
);

has '_handlers' => (
    is         => 'ro',
    isa        => 'HashRef',
    lazy_build => 1,
);

sub handle_request {
    my ( $self, $request ) = @_;
    my $params = OpenID::Lite::Message->from_request($request);
    my $mode   = $params->get('mode');
    return $self->ERROR(q{Missing parameter, "mode"}) unless $mode;
    my $handler = $self->_get_handler_for($mode);
    return $self->ERROR( sprintf q{Invalid paramter, "mode", "%s"}, $mode )
        unless $handler;
    my $result = $handler->handle_request($params)
        or return $self->ERROR( $handler->errstr );
    return $result;
}

sub _get_handler_for {
    my ( $self, $mode ) = @_;
    if ( $mode eq ASSOCIATION ) {
        return $self->_handlers->{associate};
    }
    elsif ( $mode eq CHECK_AUTHENTICATION ) {
        return $self->_handlers->{checkauth};
    }
    elsif ($mode eq CHECKID_SETUP
        || $mode eq CHECKID_IMMEDIATE )
    {
        return $self->_handlers->{checkid};
    }
    return;
}

sub _build__handlers {
    my $self     = shift;
    my $handlers = {};
    $handlers->{associate}
        = OpenID::Lite::Provider::Handler::Association->new(
        assoc_builder => $self->_assoc_builder, );

    $handlers->{checkauth} = OpenID::Lite::Provider::Handler::CheckAuth->new(
        assoc_builder => $self->_assoc_builder, );

    $handlers->{checkid} = OpenID::Lite::Provider::Handler::CheckID->new(
        assoc_builder => $self->_assoc_builder,
        setup_url     => $self->setup_url,
        endpoint_url  => $self->endpoint_url,
        get_user      => $self->get_user,
        get_identity  => $self->get_identity,
        is_identity   => $self->is_identity,
        is_trusted    => $self->is_trusted,
    );
    return $handlers;
}

sub _build__assoc_builder {
    my $self          = shift;
    my $assoc_builder = OpenID::Lite::Provider::AssociationBuilder->new(
        server_secret       => $self->server_secret,
        secret_lifetime     => $self->secret_lifetime,
        secret_gen_interval => $self->secret_gen_interval,
        get_server_secret   => $self->get_server_secret,
    );
    return $assoc_builder;
}

sub make_op_initiated_assertion {
    my ( $self, $rp_realm, $identifier ) = @_;
    my $urls = $self->discover_rp($rp_realm)
        or return;
    return $self->ERROR( sprintf q{url not found for realm, "%s"}, $rp_realm )
        unless @$urls > 0;
    return $self->make_rp_login_assertion( $rp_realm, $urls->[0],
        $identifier );
}

sub make_op_initiated_assertion_without_discovery {
    my ( $self, $rp_realm, $url, $identifier ) = @_;

    my $message = OpenID::Lite::Message->new;
    $message->set( ns         => SIGNON_2_0 );
    $message->set( realm      => $rp_realm );
    $message->set( claimed_id => $identifier );
    $message->set( identity   => $identifier );
    $message->set( return_to  => $url );

    return OpenID::Lite::Provider::Response->new(
        type          => POSITIVE_ASSERTION,
        req_params    => $message,
        res_params    => $message,
        assoc_builder => $self->_assoc_builder,
        endpoint_url  => $self->endpoint_url,
    )->make_singed_url();
}

sub discover_rp {
    my ( $self, $rp_realm ) = @_;
    unless ( ref($rp_realm) eq 'OpenID::Lite::Realm' ) {
        $rp_realm = OpenID::Lite::Realm->parse($rp_realm)
            or
            return $self->ERROR( sprintf q{Invalid realm "%s"}, $rp_realm );
    }
    my $return_to_urls
        = $self->_discoverer->discover( $rp_realm->build_discovery_url )
        or return $self->ERROR( $self->_discover->errstr );
    return $return_to_urls;
}

sub _build__discoverer {
    my $self = shift;
    return OpenID::Lite::Provider::Discover->new( agent => $self->agent );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME

OpenID::Lite::Provider - OP class

=head1 SYNOPSIS

OpenID Controller

    package YourApp::OpenIDController;

    my $op = OpenID::Lite::Provider->new(
        endpoint_url => q{http://yourapp.com/openid},
        setup_url    => q{http://yourapp.com/setup},
    );

    # server endpoint
    sub openid {
        my $self = shift;
        my $result = $op->handle_request( $self->request );
        if ( $result->is_for_setup ) {

            # save the parameters into session
            # this is just an example, you can take other ways.
            # for example, use query-string parameter.
            $self->session->set( 'openid.checkid' => $result );

            # required setup and
            # show decision page

            # 1. redirect to action that is for setup
            $self->redirect_to( $self->uri_to( action => 'setup' ) );
            return;

            # 2. or directly show setup page.
            $self->view->render('decision_page', {
                realm => $result->find_requesting_realm,
            } );

        } elsif ( $result->requires_setup ) {

            return $self->redirect_to( $result->make_setup_url() );

        } elsif ( $result->is_positive_assertion ) {

            # do extension processes if you need.
            my $sreg_req = OpenID::Lite::Extension::SREG::Request->from_result($result);
            $sreg_req->request_fields();
            my $sreg_res = OpenID::Lite::Extension::SREG::Response->new();
            $result->add_extension( $sreg_res );

            # redirect back to RP with signed params.
            return $self->redirect_to( $result->make_signed_url() );

        } elsif ( $result->is_for_direct_communication ) {

            # direct communication response
            $self->view->content( $result->content );

        } elsif ( $result->is_checkid_error ) {

            # show error page on checkid
            $self->log->debug( $result->errstr );
            $self->view->render('error');

        }
    }

    sub setup {
        my $self = shift;
        my $checkid_result = $self->session->get('openid.checkid');
    }

    sub user_cancel {
        my $self = shift;
        my $checkid_result = $self->session->get('openid.checkid');
        return $self->redirect_to( $checkid_result->make_cancel_url() );
    }

    sub user_approved {
        my $self = shift;
        my $checkid_result = $self->session->get('openid.checkid');

        # redirect to RP as positive-assertion
        my $sreg_req = OpenID::Lite::Extension::SREG::Request->extract($checkid_result);
        $sreg_req->request_fields();
        my $sreg_res = OpenID::Lite::Extension::SREG::Response->new();
        $result->add_extension( $sreg_res );

        return $self->redirect_to( $checkid_result->make_signed_url() );

    }

    1;

Application Root

    package YourApp::RootController;

    sub root {
        my $self = shift;
    }
    1;

User Page

    package YourApp::UserController;

    sub user {
        my ( $self, $user_id ) = @_;
    }

    1;

=head1 NAME

OpenID::Lite::Provider - OpenID Provider support module

=head1 SYNOPSIS

=head1 DESCRIPTION

This moduel allows you to mae OpenID Provider easily.
This supports OpenID 2.0.

'Lite' means nothing. It's to escape namespace confliction.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
