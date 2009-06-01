package OpenID::Lite::Provider::Handler::Association;

use Any::Moose;
use OpenID::Lite::Message;
use OpenID::Lite::Constants::SessionType qw(:all);
use OpenID::Lite::Constants::AssocType qw(:all);
use OpenID::Lite::Provider::AssociationBuilder;
use OpenID::Lite::SessionHandlers;
with 'OpenID::Lite::Role::ErrorHandler';

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

has '_assoc_builder' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::Provider::AssociationBuilder',
    lazy_build => 1,
);

sub handle_request {
    my ( $self, $req_params ) = @_;

    # check session type
    my $session_type = $req_params->get('session_type');
    if ( $req_params->is_openid1 ) {
        $session_type = NO_ENCRYPTION unless $session_type;
    }
    elsif ( $req_params->is_openid2 ) {
        return $self->ERROR(q{Missing parameter, "session_type".})
            unless $session_type;
    }
    else {
        return $self->ERROR(q{Missing or invalid parameter, "ns"});
    }

    # prepare session handler
    my $session = OpenID::Lite::SessionHandlers->select_session($session_type)
        or return $self->ERROR( sprintf q{Invalid session type, "%s"},
        $session_type || '' );

    # check assoc_type
    my $assoc_type = $req_params->get('assoc_type') || '';
    unless ( $assoc_type && $req_params->is_openid1 ) {
        $assoc_type = HMAC_SHA1;
    }
    unless ( $session->can_handle_assoc_type($assoc_type) ) {
        if ( $req_params->is_openid1 ) {
            return $self->ERROR(
                q{Invalid assoc_type and session_type combination.});
        }
        my $unsupported = OpenID::Lite::Message->new;
        $unsupported->set( ns => $req_params->ns );
        $unsupported->set(
            error => q{Invalid assoc_type and session_type combination.} );
        $unsupported->set( error_code => q{unsupported-type} );

        # set preferred type
        #$unsupported->set( assoc_type   => );
        #$unsupported->set( session_type => );
        return $unsupported;
    }

    # build association
    my $assoc = $self->_assoc_builder->build_association(
        type     => $assoc_type,
        lifetime => $self->secret_lifetime,
        dumb     => 0,
    );

#my $assoc = OpenID::Lite::Association->gen($assoc_type, $self->secret_lifetime);

    my $res_params = OpenID::Lite::Message->new;
    $res_params->set( ns           => $req_params->ns );
    $res_params->set( expires_in   => $assoc->expires_in );
    $res_params->set( assoc_handle => $assoc->handle );
    $res_params->set( assoc_type   => $assoc->type );

    $session->set_response_params( $req_params, $res_params, $assoc );

    #$self->store->save_association($assoc);

    return $res_params;
}

sub _build__assoc_builder {
    my $self = shift;
    return OpenID::Lite::Provider::AssociationBuilder->new(
        server_secret => $self->server_secret, 
    );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

