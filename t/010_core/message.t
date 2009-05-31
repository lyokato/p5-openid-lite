use strict;
use warnings;

use Test::More tests => 2;                      # last test to print
use OpenID::Lite::Message;

my $params = OpenID::Lite::Message->new;
$params->set( mode => 'error' );
$params->set( error => q{This is an example message} );

is($params->to_key_value,
q{error:This is an example message
mode:error
}, "to_key_value encoding check");
is($params->to_post_body, q{openid.error=This%20is%20an%20example%20message&openid.mode=error}, "to_post_body encoding check");
