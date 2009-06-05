package OpenID::Lite::Nonce;

use strict;
use warnings;

use String::Random;
use POSIX;
use Time::Local;

my $SKEW = 60 * 60 * 5;

sub gen_nonce {
    my $class = shift;
    my $t     = shift;
    $t = time() unless defined $t;
    my $time   = POSIX::strftime( q{%FT%TZ}, gmtime($t) );
    my $random = String::Random->new;
    my $salt   = $random->randregex('[a-zA-Z0-9]{6}');
    return $time . $salt;
}

sub split_nonce {
    my $class     = shift;
    my $nonce     = shift;
    my $pos       = length(q{0000-00-00T00:00:00Z});
    my $timestamp = substr( $nonce, 0, $pos );
    return if length($timestamp) < $pos;
    return unless $timestamp =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
    my $time;
    eval { $time = Time::Local::timegm($6, $5, $4, $3, $2 - 1, $1); };
    if ($@) { return; }
    my $rest = substr( $nonce, $pos );
    return ( $time, $rest );
}

sub skew {
    my ( $class, $new_skew ) = @_;
    $SKEW = $new_skew if $new_skew;
    return $SKEW;
}

sub check_timestamp {
    my ( $class, $nonce_str, $allowed_skew, $now ) = @_;
    $allowed_skew = $class->skew() unless defined $allowed_skew;
    $now          = time()         unless defined $now;
    my ( $stamp, $foo ) = $class->split_nonce($nonce_str)
        or return 0;
    my $past   = $now - $allowed_skew;
    my $future = $now + $allowed_skew;
    return ( $past <= $stamp && $stamp <= $future ) ? 1 : 0;
}

1;

