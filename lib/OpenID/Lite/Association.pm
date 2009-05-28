package OpenID::Lite::Association;

use Any::Moose;

use OpenID::Lite::Types qw(AssocType SessionType);
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);
use String::Random;
use MIME::Base64;

has 'handle' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'secret' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'type' => (
    is       => 'rw',
    isa      => AssocType,
    required => 1,
);

has 'expires_in' => (
    is => 'rw',
    isa => 'Int',
    required => 1,
);

has 'issued' => (
    is => 'rw',
    isa => 'Int',
    required => 1,
);

sub gen {
    my $class      = shift;
    my $assoc_type = shift;
    my $lifetime   = shift;
    my $issued     = shift || time();
    my $handle = $class->gen_handle($assoc_type);
    my $secret = $class->gen_secret($assoc_type);

    my $assoc = OpenID::Lite::Association->new(
        secret     => $secret,
        handle     => $handle,
        type       => $assoc_type,
        expires_in => $lifetime,
        issued     => $issued,
    );
    return $assoc;
}

sub gen_handle {
    my $class = shift;
    my $assoc_type = shift;
    my $random     = String::Random->new;
    my $uniq       = MIME::Base64::encode_base64(
        $random->randomregex(q![a-zA-Z0-9]{4}!) );
    $uniq =~ s/\s+//g;
    my $handle = sprintf( '{%s}{%x}{%s}', $assoc_type, time(), $uniq );
    return $handle;
}

sub gen_secret {
    my $class = shift;
    my $assoc_type = shift;
    my $length     = $class->get_secret_size($assoc_type);
    return unless $length;
    my $random = String::Random->new;
    my $secret = $random->randomregex( sprintf '[a-zA-Z0-9]{%d}', $length );
    return $secret;
}

sub get_secret_size {
    my $class = shift;
    my $assoc_type = shift;
    if ( $assoc_type eq HMAC_SHA1 ) {
        return 20;
    }
    elsif ( $assoc_type eq HMAC_SHA256 ) {
        return 32;
    }
    return;
}

sub expires_at {
    my $self = shift;
    return ( $self->issued + $self->expires_in );
}

sub is_expired {
    my $self = shift;
    return ( $self->expires_at < time() );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

