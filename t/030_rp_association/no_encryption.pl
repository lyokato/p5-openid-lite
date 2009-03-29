use strict;
use warnings;

use Test::More tests => 1;    # last test to print
use OpenID::Lite::RelyingParty::Associator;
use OpenID::Lite::RelyingParty::Discover::Service;
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);
use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION DH_SHA1 DH_SHA256);

my $service = OpenID::Lite::RelyingParty::Discover::Service->new(
    claimed_identifier => "https://id.mixi.jp/lyokato",
    types              => [
        "http://specs.openid.net/auth/2.0/signon",
        "http://openid.net/sreg/1.0",
        "http://openid.net/extensions/sreg/1.1",
        "http://openid.net/srv/ax/1.0",
    ],
    uris => ["https://mixi.jp/openid_server.pl"],
);

my $assoc = OpenID::Lite::RelyingParty::Associator->new(
    assoc_type   => HMAC_SHA1,
    session_type => NO_ENCRYPTION,
);
my $association = $assoc->associate($service);
is ($association->handle, q{});

