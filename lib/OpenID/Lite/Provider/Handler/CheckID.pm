package OpenID::Lite::Provider::Handler::CheckID;

use Any::Moose;
use OpenID::Lite::Constants::ModeType qw(:all);
use OpenID::Lite::Constants::Namespace qw(IDENTIFIER_SELECT);
use OpenID::Lite::Message;
use OpenID::Lite::Realm;
use OpenID::Lite::Util::Nonce qw(gen_nonce);
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

has 'redirect_for_setup' => (
    is      => 'ro',
    isa     => 'Bool',
    default => 1,
);

# callbacks
has 'get_user' => ();
has 'get_identity' => ();
has 'is_identity' => ();
has 'is_trusted' => ();

sub handle_request {

    my ( $self, $req_params ) = @_;

    my $return_to = $req_params->get('return_to');
    return $self->ERROR(q{Missing parameter, "return_to"})
        unless $return_to && $return_to =~ m!https?://!;

    my $realm_key = $req_params->is_openid2
        ? 'realm'
        : 'trust_root';
    my $realm = $req_params->get($realm_key);

    if ( $realm ) {
        return $self->ERROR(q{Invalid realm or return_to.})
            unless OpenID::Lite::Ream->check_url($realm, $return_to);
    } else {
        $realm = $return_to;
    }
    $realm =~ s/\?.*//;

    my $user = $self->get_user->();

    my $identity = $req_params->get('identity');
    return $self->ERROR(q{Missing parameter, "identity"})
        unless $identity;

    my $res_params = OpenID::Lite::Message->new;

    my $is_identity = 0;
    if ( $identity eq IDENTIFIER_SELECT )  {
        $identity = $self->get_identity->($user);
        $is_identity = 0;
    } else {
        $is_identity = $self->is_identity->($user, $identity);
    }
    my $is_trusted  = $self->is_trusted->($user, $realm)
        if $is_identity;
    if ( $is_trusted ) {
        # $url = $self->gen_signed_response();
        return;
    }

    my $setup_url = URI->new( $self->setup_url );

    my $mode = $req_params->get('mode');
    if ( $mode eq CHECKID_IMMEDIATE ) {
        if ( $req_params->is_openid2 ) {
            $res_params->set( ns => $req_params->get('ns') );
            $res_params->set( mode => SETUP_NEEDED );
        } else {
            $res_params->set( mode => ID_RES );
            $res_params->set( user_setup_url => $setup_url );
        }
        # return as error-redirect
        return;
    }

    if ( $self->redirect_for_setup ) {
        # return setup_url as redirect-mode
        return;
    } else {
        # return setup params as setup-mode
        return;
    }
}

sub signed_return_url {
    my ( $self, %args ) = @_;
    my $identity     = $args{identity};
    my $claimed_id   = $args{claimed_id};
    my $return_to    = $args{return_to};
    my $assoc_handle = $args{assoc_handle};
    my $ns           = $args{ns};
    my $extra        = $args{extra}||{};
    my $realm        = $args{realm}||$args{trust_root};

    unless ( OpenID::Lite::Realm->check_url($realm, $return_to) ) {
        return $self->ERROR(q{});
    }

    # check association
    my $assoc;
    my $invalidate_handle;
    if ( $assoc_handle ) {
        # my $found = $self->store->find_association_by_handle($assoc_handle);
        # if ( $found && !$found->is_expired ) {
        #    $assoc = $found;
        # }
    }

    unless ( $assoc ) {
        # $assoc = $self->generate_assoc();
        # $invalidate_handle = $assoc->handle if $assoc;
    }

    $claimed_id ||= $identity;
    $claimed_id = $identity if $claimed_id eq IDENTIFIER_SELECT;

    my $res_params = OpenID::Lite::Message->new;
    $res_params->set( ns => $ns ) if $ns;

    $res_params->set( mode              => ID_RES         );
    $res_params->set( identity          => $identity      );
    $res_params->set( return_to         => $return_to     );
    $res_params->set( assoc_handle      => $assoc->handle );

    $res_params->set( invalidate_handle => $invalidate_handle )
        if $invalidate_handle;

    if ( $res_params->is_openid2 ) {
        $res_params->set( claimed_id     => $claimed_id         );
        $res_params->set( response_nonce => gen_nonce()         );
        $res_params->set( op_endpoint    => $self->endpoint_url );
    }

    my $signed = q{};
    $res_params->set( signed => $signed );
    my $signature_method = OpenID::Lite::SignatureMethods->select_method($assoc->type);
    my $signature = $signature_method->sign($assoc->secret, $res_params);
    $res_params->set( sig => $signature );
    return $res_params;
}

sub cancel_return_url {
    my ( $self, $return_to ) = @_;
    my $url = URI->new( $return_to );
    # openid.ns =>
    $url->query_form( 'openid.mode' => CANCEL );
    return $url->as_string;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

