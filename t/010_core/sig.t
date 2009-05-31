use strict;
use warnings;

use Test::More tests => 4; 

use OpenID::Lite::Message;
use OpenID::Lite::SignatureMethods;


my $assoc_type = q{HMAC-SHA1};
my $secret = q{sekrit};
my $assoc_handle = '{vroom}{zoom}';
my $sig = q{uXoT1qm62/BB09Xbj98TQ8mlBco=};

my $params = OpenID::Lite::Message->new;
$params->set( foo          => q{bar} );
$params->set( apple        => q{orange} );
$params->set( assoc_handle => '{vroom}{zoom}' );

$params->set_signed();
is($params->get('signed'), q{apple,assoc_handle,foo,signed});


my $signature_method = OpenID::Lite::SignatureMethods->select_method($assoc_type);
is( $signature_method->sign($secret, $params), $sig, q{sig is not expected.});

$params->set( sig => q{uXoT1qm62/BB09Xbj98TQ8mlBco=} );
ok( $signature_method->verify($secret, $params), q{failed verifying} );


# set bad sig
$params->set( sig => q{uXoT1qm62/BB09Xbj98TQ8mlBco=BOGUS} );
ok( !$signature_method->verify($secret, $params), q{should failed verifying} );
