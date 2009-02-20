package OpenID::Lite::Util::Nonce;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = ( all => [qw(gen_nonce split_nonce)] );
our @EXPORT_OK = map { @$_ } values %EXPORT_TAGS;

use String::Random;
use POSIX;
use Time::Local;

sub gen_nonce {
    $time = POSIX::strftime(q{%FT%TZ}, gmtime());
    my $random = String::Random->new;
    my $salt = $random->randomregex('[a-zA-Z0-9]{6}');
    return $time.$salt;
}

sub split_nonce {
    my $nonce = shift; 
    my $timestamp = substr($nonce, 0, $pos)
    return if length($timestamp) < $pos;
    return unless $timestamp =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
    my $time = timegm( POSIX::strptime( $timestamp, q{%FT%TZ} ) );
    my $rest = substr($nonce, $pos);
    return ($time, $rest);
}


1;

