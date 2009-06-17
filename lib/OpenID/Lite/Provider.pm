package OpenID::Lite::Provider;

use Any::Moose;
use OpenID::Lite::Message;
use OpenID::Lite::Realm;
use OpenID::Lite::Provider::Discover;
use OpenID::Lite::Provider::AssociationBuilder;
use OpenID::Lite::Provider::Handler::Association;
use OpenID::Lite::Provider::Handler::CheckAuth;
use OpenID::Lite::Provider::Handler::CheckID;
use OpenID::Lite::Constants::ModeType qw(:all);

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

has 'gen_server_secret' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub { sub { return ''; } },
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
    return $handler->handle_request($params);
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
    my $self          = shift;
    my $handlers      = {};
    my $assoc_builder = OpenID::Lite::Provider::AssociationBuilder->new(
        server_secret       => $self->server_secret,
        secret_lifetime     => $self->secret_lifetime,
        secret_gen_interval => $self->secret_gen_interval,
        get_server_secret   => $self->get_server_secret,
    );
    $handlers->{associate}
        = OpenID::Lite::Provider::Handler::Association->new(
        assoc_builder => $assoc_builder, );

    $handlers->{checkauth} = OpenID::Lite::Provider::Handler::CheckAuth->new(
        assoc_builder => $assoc_builder, );

    $handlers->{checkid} = OpenID::Lite::Provider::Handler::CheckID->new(
        assoc_builder      => $assoc_builder,
        setup_url          => $self->setup_url,
        endpoint_url       => $self->endpoint_url,
        get_user           => $self->get_user,
        get_identity       => $self->get_identity,
        is_identity        => $self->is_identity,
        is_trusted         => $self->is_trusted,
    );
    return $handlers;
}

sub make_rp_login_assertion_with_realm {
    my ( $self, $rp_realm ) = @_;
    my $urls = $self->discover_rp($rp_realm)
        or return;
    return $self->ERROR( sprintf q{url not found for realm, "%s"}, $rp_realm )
        unless @$urls > 0;
    return $self->make_rp_login_assertion( $urls->[0] );
}

sub make_rp_login_assertion {
    my ( $self, $url ) = @_;
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

=head1 DESCRIPTION

=cut
