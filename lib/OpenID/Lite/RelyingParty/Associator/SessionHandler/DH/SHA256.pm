package OpenID::Lite::RelyingParty::Associator::SessionHandler::DH::SHA256;

use Mouse;
extends 'OpenID::Lite::RelyingParty::Associator::SessionHandler::DH';

use Digest::SHA ();
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA256);
use OpenID::Lite::Constants::SessionType qw(DH_SHA256);

has '+_session_type' => (
    is      => 'ro',
    isa     => 'Str',
    default => DH_SHA256,
);

has '+_allowed_assoc_types' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [HMAC_SHA256] },
);

override '_hash' => sub {
    my ( $self, $dh_sec ) = @_;
    return Digest::SHA::sha256($dh_sec);
};

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

