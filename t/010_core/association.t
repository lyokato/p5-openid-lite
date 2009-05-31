use strict;
use warnings;

use Test::More tests => 16;    # last test to print

use OpenID::Lite::Association::Builder::HMAC;

my $builder = OpenID::Lite::Association::Builder::HMAC->new(

);

sub test_secret {
    my ( $type, $dumb, $length ) = @_;
    my $assoc = $builder->build_association( $type, $dumb );
    ok( $assoc, sprintf(q{failed to build association}, $builder->errstr||'') );
    is( length( $assoc->secret ),                     $length, q{secret length is wrong.} );
    my $secret = $builder->secret_of_handle($assoc->handle, $dumb);
    ok($secret, sprintf(q{Failed to get secret "%s" for handle "%s"}, $builder->errstr||'', $assoc->handle));
    is($secret, $assoc->secret, q{failed to get same secret} );
}

&test_secret( 'HMAC-SHA1',   0, 20 );
&test_secret( 'HMAC-SHA1',   1, 20 );
&test_secret( 'HMAC-SHA256', 0, 32 );
&test_secret( 'HMAC-SHA256', 1, 32 );

