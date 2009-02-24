package OpenID::Lite::RelyingParty::Associator::SessionHandler::DH::SHA1;

use Mouse;
extends 'OpenID::Lite::RelyingParty::Associator::SessionHandler::DH';

use Digest::SHA ();
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1);
use OpenID::Lite::Constants::SessionType qw(DH_SHA1);

has '+_session_type' => (
    is      => 'ro',
    isa     => 'Str',
    default => DH_SHA1,
);

has '+_allowed_assoc_types' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [HMAC_SHA1] },
);

has '+_secret_length' => (
    is      => 'ro',
    isa     => 'Int',
    default => 20,
);

override '_hash' => sub {
    my ( $self, $dh_sec ) = @_;
    return Digest::SHA::sha1($dh_sec);
};

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

