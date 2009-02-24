package OpenID::Lite::Association;

use Mouse;

use OpenID::Lite::Types qw(AssocType SessionType);

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

sub expires_at {
    my $self = shift;
    return ( $self->issued + $self->expires_in );
}

sub is_expired {
    my $self = shift;
    return ( $self->expires_at < time() );
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

