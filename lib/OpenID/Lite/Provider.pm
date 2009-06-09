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

has 'redirect_for_setup' => (
    is      => 'ro',
    isa     => 'Bool',
    default => 1,
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
    default    => sub { +{} },
    lazy_build => 1,
);

sub handle_request {
    my ( $self, $request ) = @_;
    my $params = OpenID::Lite::Message->from_request($request);
    my $mode   = $params->get('mode');
    return $self->ERROR(q{Missing parameter, "mode"}) unless $mode;
    my $handler = $self->_get_handler_for($mode);
    return $self->ERROR( sprintf q{Invalid paramter, "mode", "%s"}, $mode )
        unless $mode;
    $handler->handle_request($params);
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
        redirect_for_setup => $self->redirect_for_setup,
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

