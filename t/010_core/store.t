use strict;
use warnings;

#use Test::More tests => 1;                      # last test to print
use Test::More qw(no_plan);

use OpenID::Lite::RelyingParty::Store::OnMemory;
use OpenID::Lite::Nonce;
use OpenID::Lite::Association;
use String::Random;

my $store = OpenID::Lite::RelyingParty::Store::OnMemory->new;

sub _gen_random {
    my $digit = shift;
    my $rand = String::Random->new;
    return $rand->randregex(sprintf '[a-zA-Z0-9]{%d}', $digit);
}

sub _gen_assoc {
    my ( $issued, $lifetime ) = @_;
    $issued = 0 unless defined $issued;
    $lifetime = 600 unless defined $lifetime;
    my $handle = &_gen_random(20);
    my $secret = &_gen_random(128);
    return OpenID::Lite::Association->new(
        handle     => $handle,
        type       => q{HMAC-SHA1},
        secret     => $secret,
        issued     => time() + $issued,
        expires_in => $lifetime,
    );
}

sub _check_retrieve {
    my ( $url, $handle, $expected ) = @_;
    my $ret_assoc = $store->get_association($url, $handle);
    if ( $expected ) {
        is($ret_assoc->handle, $expected->handle);
        is($ret_assoc->secret, $expected->secret);
    } else {
        ok(!$ret_assoc);
    }
}

sub _check_remove {
    my ( $url, $handle, $expected ) = @_;
    my $present = $store->remove_association($url, $handle);
    is($present, $expected);
}

sub test_store {
    my $server_url = q{http://www.myopenid.com/openid};
    my $assoc = &_gen_assoc();
    &_check_retrieve($server_url);
    $store->store_association($server_url, $assoc);
    &_check_retrieve($server_url, undef, $assoc);
    &_check_retrieve($server_url, undef, $assoc);

    $store->store_association($server_url, $assoc);
    &_check_retrieve($server_url, undef, $assoc);

    &_check_remove($server_url, $assoc->handle.'x', 0);
    &_check_remove('x'.$server_url, $assoc->handle, 0);

    &_check_remove($server_url, $assoc->handle, 1);
    &_check_remove($server_url, $assoc->handle, 0);

    $store->store_association($server_url, $assoc);
    my $assoc2 = &_gen_assoc(1);
    $store->store_association($server_url, $assoc2);

    &_check_retrieve($server_url, undef, $assoc2);
    &_check_retrieve($server_url, $assoc->handle, $assoc);
    &_check_retrieve($server_url, $assoc2->handle, $assoc2);

    my $assoc3 = &_gen_assoc(2, 100);
    $store->store_association($server_url, $assoc3);
    &_check_retrieve($server_url, undef, $assoc3);
    &_check_retrieve($server_url, $assoc->handle, $assoc);
    &_check_retrieve($server_url, $assoc2->handle, $assoc2);
    &_check_retrieve($server_url, $assoc3->handle, $assoc3);

    &_check_remove($server_url, $assoc2->handle, 1);
    &_check_retrieve($server_url, undef, $assoc3);
    &_check_retrieve($server_url, $assoc->handle, $assoc);
    &_check_retrieve($server_url, $assoc2->handle, 0);
    &_check_retrieve($server_url, $assoc3->handle, $assoc3);

    &_check_remove($server_url, $assoc2->handle, 0);
    &_check_remove($server_url, $assoc3->handle, 1);

    &_check_retrieve($server_url, undef, $assoc);
    &_check_retrieve($server_url, $assoc->handle, $assoc);
    &_check_retrieve($server_url, $assoc2->handle, 0);
    &_check_retrieve($server_url, $assoc3->handle, 0);

    &_check_remove($server_url, $assoc2->handle, 0);
    &_check_remove($server_url, $assoc->handle,  1);
    &_check_remove($server_url, $assoc3->handle, 0);

    &_check_retrieve($server_url, undef, 0);
    &_check_retrieve($server_url, $assoc->handle, 0);
    &_check_retrieve($server_url, $assoc2->handle, 0);
    &_check_retrieve($server_url, $assoc3->handle, 0);

    &_check_remove($server_url, $assoc2->handle, 0);
    &_check_remove($server_url, $assoc->handle,  0);
    &_check_remove($server_url, $assoc3->handle, 0);

    my $assoc_valid1   = &_gen_assoc(-3600, 7200);
    my $assoc_valid2   = &_gen_assoc(-5);
    my $assoc_expired1 = &_gen_assoc(-7200, 3600);
    my $assoc_expired2 = &_gen_assoc(-7200, 3600);

    $store->cleanup_associations();
    $store->store_association($server_url."1", $assoc_valid1);
    $store->store_association($server_url."1", $assoc_expired1);
    $store->store_association($server_url."2", $assoc_expired2);
    $store->store_association($server_url."3", $assoc_valid2);
    my $cleaned = $store->cleanup_associations();
    is($cleaned, 2);
}

sub _check_use_nonce {
    my ( $nonce, $expected, $server_url, $msg ) = @_;
    my ($stamp, $salt) = OpenID::Lite::Nonce->split_nonce($nonce);
    my $actual = $store->use_nonce($server_url, $stamp, $salt);
    is($actual, $expected, $msg||'');
}

sub test_nonce {
    my $server_url = q{http://www.myopenid.com/openid};
    for my $url ( $server_url, '' ) {
        my $nonce1 = OpenID::Lite::Nonce->gen_nonce();
        &_check_use_nonce($nonce1, 1, $url);
        &_check_use_nonce($nonce1, 0, $url);
        &_check_use_nonce($nonce1, 0, $url);
        my $old_nonce = OpenID::Lite::Nonce->gen_nonce(3600);
        &_check_use_nonce($old_nonce, 0, $url);
    }
    my $now = time();
    my $old_nonce1 = OpenID::Lite::Nonce->gen_nonce($now - 20000);
    my $old_nonce2 = OpenID::Lite::Nonce->gen_nonce($now - 10000);
    my $recent_nonce = OpenID::Lite::Nonce->gen_nonce($now - 600);

    my $orig_skew = OpenID::Lite::Nonce->skew;
    OpenID::Lite::Nonce->skew(0);
    $store->cleanup_nonces();
    OpenID::Lite::Nonce->skew(1000000);
    my ($ts,$salt);
    ($ts, $salt) = OpenID::Lite::Nonce->split_nonce($old_nonce1);
    ok($store->use_nonce($server_url, $ts, $salt), q{old_nonce1});
    ($ts, $salt) = OpenID::Lite::Nonce->split_nonce($old_nonce2);
    ok($store->use_nonce($server_url, $ts, $salt), q{old_nonce2});
    ($ts, $salt) = OpenID::Lite::Nonce->split_nonce($recent_nonce);
    ok($store->use_nonce($server_url, $ts, $salt), q{recent_nonce});

    OpenID::Lite::Nonce->skew(1000);
    my $cleaned = $store->cleanup_nonces();
    is($cleaned, 2);

    OpenID::Lite::Nonce->skew(100000);
    ($ts, $salt) = OpenID::Lite::Nonce->split_nonce($old_nonce1);
    ok($store->use_nonce($server_url, $ts, $salt), q{old_nonce1 after cleanup});
    ($ts, $salt) = OpenID::Lite::Nonce->split_nonce($old_nonce2);
    ok($store->use_nonce($server_url, $ts, $salt), q{old_nonce2 after cleanup});
    ($ts, $salt) = OpenID::Lite::Nonce->split_nonce($recent_nonce);
    ok(!$store->use_nonce($server_url, $ts, $salt), q{recent_nonce after cleanup});

    OpenID::Lite::Nonce->skew($orig_skew);
}


&test_store();
&test_nonce();

