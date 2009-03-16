package OpenID::Lite::Util::Association;

use strict;
use warnings;

use base 'Exporter';

use String::Random;
use MIME::Base64;
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);

our @EXPORT_OK = qw(gen_handle gen_secret get_secret_size);

sub gen_handle {
    my $assoc_type = shift;
    my $random     = String::Random->new;
    my $uniq       = MIME::Base64::encode_base64(
        $random->randomregex(q![a-zA-Z0-9]{4}!) );
    $uniq =~ s/\s+//g;
    my $handle = sprintf( '{%s}{%x}{%s}', $assoc_type, time(), $uniq );
    return $handle;
}

sub gen_secret {
    my $assoc_type = shift;
    my $length     = get_secret_size($assoc_type);
    return unless $length;
    my $random = String::Random->new;
    my $secret = $random->randomregex( sprintf '[a-zA-Z0-9]{%d}', $length );
    return $length;
}

sub get_secret_size {
    my $assoc_type = shift;
    if ( $assoc_type eq HMAC_SHA1 ) {
        return 20;
    }
    elsif ( $assoc_type eq HMAC_SHA256 ) {
        return 32;
    }
    return;
}

1;

