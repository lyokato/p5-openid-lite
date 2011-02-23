use strict;
use warnings;

use Test::More tests => 1;                      # last test to print
use OpenID::Lite::Util::URI;
use URI;

my $uri = URI->new("https://me.yahoo.co.jp/a/Z.abcd123456#frag");
ok( OpenID::Lite::Util::URI->is_uri($uri) );



