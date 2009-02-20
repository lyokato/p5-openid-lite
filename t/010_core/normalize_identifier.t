use strict;
use warnings;
use Test::Base;
use OpenID::Lite::Identifier;

plan tests => 2 * blocks;

filters {
    userinput  => 'chomp',
    identifier => 'chomp',
    is_xri     => 'chomp',
};

run {
    my $block      = shift;
    my $normalized = OpenID::Lite::Identifier->normalize( $block->userinput );
    is( $normalized->as_string, $block->identifier,
        "check normalized string" );
    is( $normalized->is_xri, $block->is_xri,
        "check if identifier is xri or not" );
};

__END__

===
--- userinput
example.com
--- identifier
http://example.com/
--- is_xri
0

===
--- userinput
http://example.com
--- identifier
http://example.com/
--- is_xri
0

===
--- userinput
https://example.com/
--- identifier
https://example.com/
--- is_xri
0

===
--- userinput
http://example.com/user
--- identifier
http://example.com/user
--- is_xri
0

===
--- userinput
http://example.com/user/
--- identifier
http://example.com/user/
--- is_xri
0

===
--- userinput
http://example.com/
--- identifier
http://example.com/
--- is_xri
0

===
--- userinput
=example
--- identifier
=example
--- is_xri
1

===
--- userinput
xri://=example
--- identifier
=example
--- is_xri
1
