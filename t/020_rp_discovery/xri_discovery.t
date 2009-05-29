use strict;
use Test::Base;

plan tests => 4 * blocks;

use OpenID::Lite::Identifier;
use OpenID::Lite::RelyingParty::Discover::Method::XRI;

filters {
    identifier         => 'chomp',
    claimed_identifier => 'chomp',
    server_url         => 'chomp',
    preferred_namespace=> 'chomp',
};

run {
    my $block      = shift;
    my $identifier = OpenID::Lite::Identifier->normalize( $block->identifier );
    my $meth       = OpenID::Lite::RelyingParty::Discover::Method::XRI->new();
    my $services   = $meth->discover($identifier);
    my $service    = $services->[0];
    is( $service->url, $block->server_url, q{server url} );
    is( $service->claimed_identifier, $block->claimed_identifier, q{claimed identifier} );
    ok( !$service->requires_compatibility_mode , q{ collect compat mode });
    is( $service->preferred_namespace, $block->preferred_namespace, q{preferred namespace} );
};

__DATA__

===
--- identifier
=zigorou
--- server_url
https://authn.fullxri.com/authentication/
--- claimed_identifier
=!545A.6972.43FA.38AD
--- preferred_namespace
http://specs.openid.net/auth/2.0

