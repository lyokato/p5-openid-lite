use strict;
use Test::Base;

plan tests => 4 * blocks;

use OpenID::Lite::Identifier;
use OpenID::Lite::RelyingParty::Discover::Method::Yadis;

filters {
    identifier         => 'chomp',
    claimed_identifier => 'chomp',
    server_url         => 'chomp',
    preferred_namespace=> 'chomp',
};

run {
    my $block      = shift;
    my $identifier = OpenID::Lite::Identifier->normalize( $block->identifier );
    my $meth       = OpenID::Lite::RelyingParty::Discover::Method::Yadis->new();
    my $services   = $meth->discover($identifier);
    my $service    = $services->[0];
    is( $service->url, $block->server_url, q{server url} );
    if ( $block->claimed_identifier ) {
        is( $service->claimed_identifier, $block->claimed_identifier );
    } else {
        ok( $service->is_op_identifier );
    }
    ok( !$service->requires_compatibility_mode );
    is( $service->preferred_namespace, $block->preferred_namespace );
};

__DATA__

===
--- identifier
https://id.mixi.jp/lyokato
--- server_url
https://mixi.jp/openid_server.pl
--- claimed_identifier
https://id.mixi.jp/lyokato
--- preferred_namespace
http://specs.openid.net/auth/2.0

===
--- identifier
mixi.jp
--- server_url
https://mixi.jp/openid_server.pl
--- claimed_identifier
--- preferred_namespace
http://specs.openid.net/auth/2.0

===
--- identifier
https://me.yahoo.co.jp/a/yE.9G9xtVfQgeBQvoCe8AyFG9sc-
--- server_url
https://open.login.yahooapis.jp/openid/op/auth
--- claimed_identifier
https://me.yahoo.co.jp/a/yE.9G9xtVfQgeBQvoCe8AyFG9sc-
--- preferred_namespace
http://specs.openid.net/auth/2.0

===
--- identifier
yahoo.co.jp
--- server_url
https://open.login.yahooapis.jp/openid/op/auth
--- claimed_identifier
--- preferred_namespace
http://specs.openid.net/auth/2.0
