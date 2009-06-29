use strict;
use warnings;

use Test::More tests => 24;
use OpenID::Lite::Nonce;

my $NONCE_RE = '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z';

sub test_gen {
    my $nonce = OpenID::Lite::Nonce->gen_nonce();
    like($nonce, qr/$NONCE_RE/);
    is(length($nonce), 26);
}

sub test_gen_time {
    my $nonce = OpenID::Lite::Nonce->gen_nonce(0);
    like($nonce, qr/$NONCE_RE/);
    is(length($nonce), 26);
    like($nonce, qr/^1970-01-01T00:00:00Z/);
}

sub test_split {
    my $s = q{1970-01-01T00:00:00Z};
    my ($t, $salt) = OpenID::Lite::Nonce->split_nonce($s);
    is($t,0);
    is($salt,'');
}

sub test_gen_split {
    my $t = 42;
    my $nonce_str = OpenID::Lite::Nonce->gen_nonce($t);
    like($nonce_str, qr/$NONCE_RE/);
    my ($at, $salt) = OpenID::Lite::Nonce->split_nonce($nonce_str);
    is(length($salt), 6);
    is($at, $t);
}

sub test_bad_split {
    my @cases = (
        '',
        '1970-01-01T00:00:00+1:00',
        #'1969-01-01T00:00:00Z',
        '1970-00-01T00:00:00Z',
        '1970.01-01T00:00:00Z',
        'Thu Sep  7 13:29:31 PDT 2006',
        'monkeys',
    );
    for my $case (@cases) {
        my ($t, $s) = OpenID::Lite::Nonce->split_nonce($case);
        ok(!$t && !$s, sprintf(q{%s should be failed to split.}, $case));
    }
}

sub test_check_timestamp {
    my @cases = (
        # exact, no allowed skew
        ['1970-01-01T00:00:00Z', 0, 0, 1],

        # exact, large skew
        ['1970-01-01T00:00:00Z', 1000, 0, 1],

        # no allowed skew, one second old
        ['1970-01-01T00:00:00Z', 0, 1, 0],

        # many seconds old, outside of skew
        ['1970-01-01T00:00:00Z', 10, 50, 0],

        # one second old, one second skew allowed
        ['1970-01-01T00:00:00Z', 1, 1, 1],

        # One second in the future, one second skew allowed
        ['1970-01-01T00:00:02Z', 1, 1, 1],

        # two seconds in the future, one second skew allowed
        ['1970-01-01T00:00:02Z', 1, 0, 0],

        # malformed nonce string
        ['monkeys', 0, 0, 0],
    );
    for my $case ( @cases ) {
        my ($nonce_str, $allowed_skew, $now, $expected) = @$case;
        my $actual = OpenID::Lite::Nonce->check_timestamp($nonce_str, $allowed_skew, $now);
        if ($expected) {
            ok($actual, sprintf(q{Should be success, %s - %s - %d}, $nonce_str, $allowed_skew, $now));
        } else {
            ok(!$actual, sprintf(q{Should fail, %s - %s - %d}, $nonce_str, $allowed_skew, $now));
        }
    }
}

&test_gen();
&test_gen_time();
&test_split();
&test_gen_split();
&test_bad_split();
&test_check_timestamp();
