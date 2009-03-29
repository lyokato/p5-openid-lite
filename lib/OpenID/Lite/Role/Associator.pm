package OpenID::Lite::Role::Associator;;

use Any::Moose '::Role';

use OpenID::Lite::Types qw(AssocType SessionType);
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA256);
use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION);

requires 'associate';

has 'assoc_type' => (
    is      => 'rw',
    isa     => AssocType,
    lazy    => 1,
    default => HMAC_SHA256,
);

has 'session_type' => (
    is      => 'rw',
    isa     => SessionType,
    lazy    => 1,
    default => NO_ENCRYPTION,
);

1;
