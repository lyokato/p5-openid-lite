use strict;
use warnings;

use Test::More tests => 44;

use OpenID::Lite::Provider::AssociationBuilder;

my $builder = OpenID::Lite::Provider::AssociationBuilder->new(
);

sub test_secret {
    my ( $type, $dumb, $length ) = @_;
    my $assoc = $builder->build_association(
        type => $type,
        dumb => $dumb );
    ok( $assoc, sprintf(q{failed to build association, "%s"}, $builder->errstr||'') );
    is( length( $assoc->secret ),                     $length, q{secret length is wrong.} );
    my $secret = $builder->secret_of_handle($assoc->handle, $dumb);
    ok($secret, sprintf(q{Failed to get secret "%s" for handle "%s"}, $builder->errstr||'', $assoc->handle));
    is($secret, $assoc->secret, q{failed to get same secret} );
    my $rebuild = $builder->build_from_handle($assoc->handle, {
            dumb => $dumb, 
        });
    ok($rebuild, sprintf(q{failed rebuild from handle, "%s"}, $builder->errstr||''));
    is($rebuild->handle,     $assoc->handle);
    is($rebuild->secret,     $assoc->secret);
    is($rebuild->type,       $assoc->type);
    is($rebuild->issued,     $assoc->issued);
    is($rebuild->expires_in, $assoc->expires_in);
}

&test_secret( 'HMAC-SHA1',   0, 20 );
&test_secret( 'HMAC-SHA1',   1, 20 );
&test_secret( 'HMAC-SHA256', 0, 32 );
&test_secret( 'HMAC-SHA256', 1, 32 );

my $builder2 = OpenID::Lite::Provider::AssociationBuilder->new(server_secret => q{hoge});
my $builder3 = OpenID::Lite::Provider::AssociationBuilder->new(server_secret => q{huga});

sub test_different_secret {
    my ( $type, $dumb ) = @_;
    my $assoc2 = $builder2->build_association(
    type => $type, 
    dumb => $dumb,
    );
    my $assoc3 = $builder3->build_association(
    type => $type, 
    dumb => $dumb,
    );
    ok($assoc2->secret ne $assoc3->secret, q{secrets should be different});
}


&test_different_secret( 'HMAC-SHA1',   0 );
&test_different_secret( 'HMAC-SHA1',   1 );
&test_different_secret( 'HMAC-SHA256', 0 );
&test_different_secret( 'HMAC-SHA256', 1 );

