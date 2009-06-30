package OpenID::Lite::Provider::Handler::CheckID;

use Any::Moose;
use OpenID::Lite::Constants::ModeType qw(:all);
use OpenID::Lite::Constants::Namespace qw(:all);
use OpenID::Lite::Constants::ProviderResponseType qw(:all);
use OpenID::Lite::Provider::Response;
use OpenID::Lite::Message;
use OpenID::Lite::Realm;
use OpenID::Lite::Provider::AssociationBuilder;
use URI;

with 'OpenID::Lite::Role::ErrorHandler';

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

has 'assoc_builder' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::Provider::AssociationBuilder',
);

# callbacks
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


sub handle_request {

    my ( $self, $req_params ) = @_;

    my $ns = $req_params->get('ns');
    my $return_to = $req_params->get('return_to');
    return $self->ERROR(q{Missing parameter, "return_to"})
        unless $return_to && $return_to =~ m!https?://!;

    my $realm_key
        = $req_params->is_openid2
        ? 'realm'
        : 'trust_root';
    my $realm = $req_params->get($realm_key);

    if ($realm) {
        return $self->ERROR(q{Invalid realm or return_to.})
            unless OpenID::Lite::Realm->check_url( $realm, $return_to );
    }
    else {
        $realm = $return_to;
    }
    $realm =~ s/\?.*//;

    my $user = $self->get_user->();

    my $identity = $req_params->get('identity');
    return $self->_build_error($req_params, q{Missing parameter, "identity"}, $ns)
        unless $identity;

    my $res_params = OpenID::Lite::Message->new;
    # XXX check
    $res_params->set( ns => $ns );
    $res_params->set( $realm_key, $realm );
    $res_params->set( claimed_id   => $req_params->get('claimed_id') );
    $res_params->set( return_to    => $req_params->get('return_to') );
    $res_params->set( assoc_handle => $req_params->get('assoc_handle') );

    my $is_identity = 0;
    if ( $identity eq IDENTIFIER_SELECT ) {
        $identity    = $self->get_identity->($user, $realm);
        $is_identity = 1;
    }
    else {
        $is_identity = $self->is_identity->( $user, $identity, $realm );
    }
    my $is_trusted = $self->is_trusted->( $user, $realm )
        if $is_identity;

    $res_params->set( identity => $identity );

    if ($is_trusted) {

        return OpenID::Lite::Provider::Response->new(
            type             => POSITIVE_ASSERTION,
            req_params       => $req_params,
            res_params       => $res_params,
            assoc_builder    => $self->assoc_builder,
            endpoint_url     => $self->endpoint_url,
            setup_url        => $self->setup_url,
        );
    }

    my $mode = $req_params->get('mode');
    if ( $mode eq CHECKID_IMMEDIATE ) {

        # XXX : TODO use setup_map
        my $setup_params = {
            return_to    => $req_params->get('return_to'),
            identity     => $identity,
            assoc_handle => $req_params->get('assoc_handle'),
        };
        $setup_params->{ ns } = $ns if $ns;
        $setup_params->{ $realm_key } = $realm;

        return OpenID::Lite::Provider::Response->new(
            type         => REQUIRES_SETUP,
            req_params   => $req_params,
            setup_url    => $self->setup_url,
            setup_params => $setup_params,
            res_params   => $res_params,
        );

    }

    return OpenID::Lite::Provider::Response->new(
        type          => SETUP,
        req_params    => $req_params,
        res_params    => $res_params,
        assoc_builder => $self->assoc_builder,
        endpoint_url  => $self->endpoint_url,
        setup_url     => $self->setup_url,
    );
}

sub _build_error {
    my ( $self, $req_params, $msg, $ns ) = @_;
    $ns ||= SIGNON_2_0;
    my $error = OpenID::Lite::Message->new();
    $error->set( ns    => $ns  );
    $error->set( error => $msg );
    my $res = OpenID::Lite::Provider::Response->new(
        type       => CHECKID_ERROR,
        req_params => $req_params,
        res_params => $error,
    );
    return $res;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

