package OpenID::Lite::Association::Builder::Random;

use Any::Moose;
use OpenID::Lite::Association;
use String::Random;
use MIME::Base64;

# ruby-openid style

sub build_association {
    my $class      = shift;
    my $assoc_type = shift;
    my $lifetime   = shift;
    my $issued     = shift || time();
    my $handle = $class->_gen_handle($assoc_type);
    my $secret = $class->_gen_secret($assoc_type);
    my $assoc = OpenID::Lite::Association->new(
        secret     => $secret,
        handle     => $handle,
        type       => $assoc_type,
        expires_in => $lifetime,
        issued     => $issued,
    );
    return $assoc;
}

sub _gen_handle {
    my $class = shift;
    my $assoc_type = shift;
    my $random     = String::Random->new;
    my $uniq       = MIME::Base64::encode_base64(
        $random->randregex(q![a-zA-Z0-9]{4}!) );
    $uniq =~ s/\s+//g;
    my $handle = sprintf( '{%s}{%x}{%s}', $assoc_type, time(), $uniq );
    return $handle;
}

sub _gen_secret {
    my $class = shift;
    my $assoc_type = shift;
    my $length     = OpenID::Lite::Association->get_secret_size($assoc_type);
    return unless $length;
    my $random = String::Random->new;
    my $secret = $random->randregex( sprintf '[a-zA-Z0-9]{%d}', $length );
    return $secret;
}


no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

