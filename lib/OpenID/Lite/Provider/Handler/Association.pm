package OpenID::Lite::Provider::Handler::Association;

use Any::Moose;

use OpenID::Lite::Types qw(AssocType);
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1);
use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION);
use OpenID::Lite::Util::Association qw(gen_handle gen_secret);
use OpenID::Lite::Association qw(gen_handle gen_secret);
use OpenID::Lite::Params;
use OpenID::Lite::Provider::Response::Direct;

has 'assoc_type' => (
    is      => 'ro',
    isa     => AssocType,
    default => HMAC_SHA1,
);

has 'session' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::SessionHandler',
    required => 1,
);

has 'secret_lifetime' => (
    is      => 'rw',
    isa     => 'Int',
    default => 14 * 24 * 60 * 60,
);

has 'store' => (
    is => 'rw',
    #does => 'Storable',
    #default => sub { OpenID::Lite::Provider::Store::Null->new },
);

sub handle_request {
    my ( $self, $req_params ) = @_;

    # check session_type and assoc_type combination
    unless ( $self->session->can_handle_assoc_type( $self->assoc_type ) ) {
        if ( $req_params->is_openid1 ) {
            return $self->ERROR(
                q{Invalid assoc_type and session_type combination.});
        }
        my $unsupported = OpenID::Lite::Params->new;
        $unsupported->set( ns => $req_params->ns );
        $unsupported->set(
            error => q{Invalid assoc_type and session_type combination.} );
        $unsupported->set( error_code => q{unsupported-type} );

        # set preferred type
        #$unsupported->set( assoc_type   => );
        #$unsupported->set( session_type => );
        return $unsupported;
    }

    my $handle = gen_handle( $self->assoc_type );
    my $secret = gen_secret( $self->assoc_type );

    my $association = OpenID::Lite::Association->new(
        secret     => $secret,
        handle     => $handle,
        type       => $self->assoc_type,
        expires_in => $self->secret_lifetime,
        issued     => time(),
    );

    my $res_params = OpenID::Lite::Params->new;
    $res_params->set( ns           => $req_params->ns );
    $res_params->set( expires_in   => $association->expires_in );
    $res_params->set( assoc_handle => $association->handle );
    $res_params->set( assoc_type   => $association->type );

    $self->session->set_response_params( $req_params, $res_params,
        $association );

    #$self->store->save_association($key, $association);

    my $res = OpenID::Lite::Provider::Response::Direct->new(
        params => $res_params, 
    );
    return $res;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

