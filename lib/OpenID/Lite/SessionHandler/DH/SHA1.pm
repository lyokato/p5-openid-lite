package OpenID::Lite::SessionHandler::DH::SHA1;

use Any::Moose;
extends 'OpenID::Lite::SessionHandler::DH';

use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1);
use OpenID::Lite::Constants::SessionType qw(DH_SHA1);

use Digest::SHA ();

has '+_session_type' => (
    is      => 'rw',
    isa     => 'Str',
    default => DH_SHA1,
);

has '+_allowed_assoc_types' => (
    is      => 'rw',
    isa     => 'ArrayRef',
    default => sub { [ HMAC_SHA1 ] },
);

has '+_secret_length' => (
    is      => 'ro',
    isa     => 'Int',
    default => 20,
);

override '_hash' => sub {
    my ( $self, $dh_sec ) = @_;
    return Digest::SHA::sha1( $dh_sec );
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


