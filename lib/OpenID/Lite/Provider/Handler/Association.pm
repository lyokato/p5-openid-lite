package OpenID::Lite::Provider::Handler::Association;

use Any::Moose;
use OpenID::Lite::Message;
use OpenID::Lite::Constants::SessionType qw(:all);
use OpenID::Lite::Constants::AssocType qw(:all);
use OpenID::Lite::Constants::Namespace qw(:all);
use OpenID::Lite::Constants::ProviderResponseType qw(:all);
use OpenID::Lite::SessionHandlers;
with 'OpenID::Lite::Role::ErrorHandler';

has 'assoc_builder' => (
    is  => 'ro',
    isa => 'OpenID::Lite::Provider::AssociationBuilder',
);

sub handle_request {
    my ( $self, $req_params ) = @_;

    # check session type
    my $session_type = $req_params->get('session_type');
    my $ns           = $req_params->get('ns');
    if ( $ns && $req_params->is_openid1 ) {
        $session_type = NO_ENCRYPTION unless $session_type;
    }
    elsif ( $req_params->is_openid2 ) {
        return $self->_build_error( $req_params,
            q{Missing parameter, "session_type".}, $ns )
            unless $session_type;
    }
    else {
        return $self->_build_error( $req_params,
            q{Missing or invalid parameter, "ns"}, $ns );
    }

    # prepare session handler
    my $session = OpenID::Lite::SessionHandlers->select_session($session_type)
        or return $self->_build_error( $req_params,
        sprintf( q{Invalid session type, "%s"}, $session_type || '' ), $ns );

    # check assoc_type
    my $assoc_type = $req_params->get('assoc_type') || '';
    unless ( $assoc_type && $req_params->is_openid1 ) {
        $assoc_type = HMAC_SHA1;
    }
    unless ( $session->can_handle_assoc_type($assoc_type) ) {
        if ( $req_params->is_openid1 ) {
            return $self->_build_error( $req_params,
                q{Invalid assoc_type and session_type combination.}, $ns );
        }
        my $unsupported = OpenID::Lite::Message->new;
        $unsupported->set( ns => $req_params->ns );
        $unsupported->set(
            error => q{Invalid assoc_type and session_type combination.} );
        $unsupported->set( error_code => q{unsupported-type} );

        # set preferred type
        #$unsupported->set( assoc_type   => );
        #$unsupported->set( session_type => );
        return OpenID::Lite::Provider::Response->new(
            type       => DIRECT,
            req_params => $req_params,
            res_params => $unsupported,
        );
    }

    # build association
    my $assoc = $self->assoc_builder->build_association(
        type => $assoc_type,
        dumb => 0,
    );

    my $res_params = OpenID::Lite::Message->new;
    $res_params->set( ns           => $ns );
    $res_params->set( expires_in   => $assoc->expires_in );
    $res_params->set( assoc_handle => $assoc->handle );
    $res_params->set( assoc_type   => $assoc->type );

    $session->set_response_params( $req_params, $res_params, $assoc );

    my $res = OpenID::Lite::Provider::Response->new(
        type       => DIRECT,
        req_params => $req_params,
        res_params => $res_params,
    );
    return $res;
}

sub _build_error {
    my ( $self, $req_params, $msg, $ns ) = @_;
    $ns ||= SIGNON_2_0;
    my $error = OpenID::Lite::Message->new();
    $error->set( ns    => $ns );
    $error->set( error => $msg );
    my $res = OpenID::Lite::Provider::Response->new(
        type       => DIRECT,
        req_params => $req_params,
        res_params => $error,
    );
    return $res;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

