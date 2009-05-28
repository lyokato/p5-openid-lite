package OpenID::Lite::Types;

use Any::Moose;
use Any::Moose 'X::Types' => [ -declare => [
    qw(
        AssocHandle
        AssocType
        SessionType
        AuthRequestMode
        AuthResponseMode
        )
] ];

use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);
use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION DH_SHA1 DH_SHA256);
use OpenID::Lite::Constants::ModeType
    qw(CHECKID_SETUP CHECKID_IMMEDIATE ID_RES SETUP_NEEDED CANCEL);

do {
    subtype AssocHandle,
        as 'Str',
        where { length $_ <= 255 }; # TODO ASCII check
};

do {
    subtype AssocType,
        as 'Str',
        where { $_ eq HMAC_SHA1 || $_ eq HMAC_SHA256 };
};

do {
    subtype SessionType,
        as 'Str',
        where { $_ eq NO_ENCRYPTION || $_ eq DH_SHA1 || $_ eq DH_SHA256 };
};

do {
    subtype AuthRequestMode,
        as 'Str',
        where { $_ eq CHECKID_SETUP || $_ eq CHECKID_IMMEDIATE };
};

do {
    subtype AuthResponseMode,
        as 'Str',
        where { $_ eq ID_RES || $_ eq SETUP_NEEDED || $_ eq CANCEL };
};

1;

