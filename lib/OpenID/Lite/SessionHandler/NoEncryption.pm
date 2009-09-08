package OpenID::Lite::SessionHandler::NoEncryption;

use Any::Moose;
extends 'OpenID::Lite::SessionHandler';

use MIME::Base64 ();

use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);
use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION);

has '+_session_type' => (
    default => NO_ENCRYPTION,
);

has '+_allowed_assoc_types' => (
    default => sub { [ HMAC_SHA1, HMAC_SHA256 ] },
);

override 'set_request_params' => sub {
    my ( $self, $service, $params ) = @_;
    unless ( $service->requires_compatibility_mode ) {
        $params->set( session_type => $self->_session_type );
    }
    return $params;
};

override 'set_response_params' => sub {
    my ( $self, $req_params, $res_params, $association ) = @_;
    my $secret = MIME::Base64::encode_base64( $association->secret );
    $secret =~ s/\s+//g;
    $res_params->set( mac_key => $secret );

    unless ( $res_params->is_openid1 ) {
        $res_params->set( session_type => $self->_session_type );
    }
};

override 'extract_secret' => sub {
    my ( $self, $params ) = @_;
    my $mac_key = $params->get('mac_key')
        or return $self->ERROR(q{Missing parameter, "mac_key".});
    return MIME::Base64::decode_base64( $mac_key );
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

