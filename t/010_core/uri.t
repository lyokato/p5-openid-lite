use strict;
use warnings;
use Test::Base;
use OpenID::Lite::Util::URI;

plan tests => 1 * blocks;

filters {
    casename => 'chomp',
    actual   => 'chomp',
    expected => 'chomp',
};

run {
    my $block = shift;
    my $u = OpenID::Lite::Util::URI->normalize($block->actual);
    if ( $block->expected eq q{fail} ) {
        ok(!$u, sprintf(q{%s should be failed}, $block->actual));
    } else {
        is($u, $block->expected, sprintf(q{%s should be normalized to %s},
            $block->actual, $block->expected));
    }
};


__END__

===
--- casename
Already normal form
--- actual
http://example.com/
--- expected
http://example.com/

===
--- casename
Add a trailing slash
--- actual
http://example.com
--- expected
http://example.com/

===
--- casename
Remove an empty port segment
--- actual
http://example.com:/
--- expected
http://example.com/

===
--- casename
Remove a default port segment
--- actual
http://example.com:80/
--- expected
http://example.com/

===
--- casename
Capitalization in host names
--- actual
http://wWw.exaMPLE.COm/
--- expected
http://www.example.com/

===
--- casename
Capitalization in scheme names
--- actual
htTP://example.com/
--- expected
http://example.com/

===
--- casename
Capitalization in percent-escaped reserved characters
--- actual
http://example.com/foo%2cbar
--- expected
http://example.com/foo%2Cbar

===
--- casename
Unescape percent-encoded unreserved characters
--- actual
http://example.com/foo%2Dbar%2dbaz
--- expected
http://example.com/foo-bar-baz

===
--- casename
remove_dot_segments example 1
--- actual
http://example.com/a/b/c/./../../g
--- expected
http://example.com/a/g

===
--- casename
remove_dot_segments example 2
--- actual
http://example.com/mid/content=5/../6
--- expected
http://example.com/mid/6

===
--- casename
remove_dot_segments: single-dot
--- actual
http://example.com/a/./b
--- expected
http://example.com/a/b

===
--- casename
remove_dot_segments: double-dot
--- actual
http://example.com/a/../b
--- expected
http://example.com/b

===
--- casename
remove_dot_segments: leading double-dot
--- actual
http://example.com/../b
--- expected
http://example.com/b

===
--- casename
remove_dot_segments: trailing single-dot
--- actual
http://example.com/a/.
--- expected
http://example.com/a/

===
--- casename
remove_dot_segments: trailing double-dot
--- actual
http://example.com/a/..
--- expected
http://example.com/

===
--- casename
remove_dot_segments: trailing single-dot-slash
--- actual
http://example.com/a/./
--- expected
http://example.com/a/

===
--- casename
remove_dot_segments: trailing double-dot-slash
--- actual
http://example.com/a/../
--- expected
http://example.com/

===
--- casename
Test of all kinds of syntax-based normalization
--- actual
hTTPS://a/./b/../b/%63/%7bfoo%7d
--- expected
https://a/b/c/%7Bfoo%7D

===
--- casename
Unsupported scheme
--- actual
ftp://example.com/
--- expected
fail

===
--- casename
Non-absolute URI
--- actual
http:/foo
--- expected
fail
