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
    is       => 'rw',
    isa      => 'Int',
    required => 1,
);

has 'issued' => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
);

sub copy {
    my $self = shift;
    return ref($self)->new(
        handle     => $self->handle,
        secret     => $self->secret,
        type       => $self->type,
        expires_in => $self->expires_in,
        issued     => $self->issued,
    );
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

