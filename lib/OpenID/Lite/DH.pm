package OpenID::Lite::DH;

use Any::Moose;
use Math::BigInt;
use Crypt::DH::GMP;
use MIME::Base64;
use Carp ();

has 'p' => (
    is  => 'ro',
    isa => 'Str',
    default => "155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443"
);

has 'g' => (
    is      => 'ro',
    isa     => 'Str',
    default => "2",
);

has 'dh' => (
    is         => 'ro',
    lazy_build => 1,
);

sub _build_dh {
    my $self = shift;
    my $dh = Crypt::DH::GMP->new;
    $dh->p($self->p);
    $dh->g($self->g);
    $dh->generate_keys();
    return $dh;
}

sub generate_keys {
    my $self = shift;
    $self->dh->generate_keys();
}

sub generate_public {
    my $self = shift;
    my $dh = $self->dh();
    my $pub = MIME::Base64::encode_base64(pack("B*", $dh->pub_key_twoc()));
    $pub =~ s/\s+//g;
    return $pub;
}

sub compute_public {
    my ( $self, $public ) = @_;
    my $dh = $self->dh();
    return pack('B*', $dh->compute_key_twoc($self->arg2bi($public)));
}

sub arg2bi {
    my ( $self, $arg ) = @_;
    return undef unless defined $arg and $arg ne "";
    return Math::BigInt->new("0") if length($arg) > 700;
    return $self->bytes2bi(MIME::Base64::decode_base64($arg));
}

sub bi2bytes {
    my ( $self, $bigint ) = @_;
    die if $bigint->is_negative;
    my $bits = $bigint->as_bin;
    die unless $bits =~ s/^0b//;
    my $prepend = (8 - length($bits) % 8) || ($bits =~ /^1/ ? 8 : 0);
    $bits = ("0" x $prepend) . $bits if $prepend;
    return pack("B*", $bits);
}

sub bytes2bi {
    my ( $self, $bytes ) = @_;
    return Math::BigInt->new("0b" . unpack("B*", $bytes));
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


