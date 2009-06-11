package OpenID::Lite::Types;

use Any::Moose;
use Any::Moose 'X::Types' => [ -declare => [
    qw(
        AssocHandle
        AssocType
        SessionType
        AuthRequestMode
        AuthResponseMode
        ProviderResponseType
        )
] ];

use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);
use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION DH_SHA1 DH_SHA256);
use OpenID::Lite::Constants::ModeType
    qw(CHECKID_SETUP CHECKID_IMMEDIATE ID_RES SETUP_NEEDED CANCEL);
use OpenID::Lite::Constants::ProviderResponseType qw(DIRECT REDIRECT SETUP);

do {
    subtype AssocHandle,
        as 'Str',
        where { $_ =~ /^[\x21-\x7e]{1,255}$/ };
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

do {
    subtype ProviderResponseType,
        as 'Str',
        where { $_ eq DIRECT || $_ eq REDIRECT || $_ eq SETUP };
};

1;

