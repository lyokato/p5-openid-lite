package OpenID::Lite::RelyingParty::Associator::SessionHandler::NoEncryption;

use Mouse;
extends 'OpenID::Lite::RelyingParty::Associator::SessionHandler';

use MIME::Base64 ();

use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);
use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION);

has '+_session_type' => (
    is      => 'rw',
    isa     => 'Str',
    default => NO_ENCRYPTION,
);

has '+_allowed_assoc_types' => (
    is      => 'rw',
    isa     => 'ArrayRef',
    default => sub { [ HMAC_SHA1, HMAC_SHA256 ] },
);

override 'extract_secret' => sub {
    my ( $self, $params ) = @_;
    return MIME::Base64::decode_base64( $params->get('mac_key') );
};

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

