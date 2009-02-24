package OpenID::Lite::RelyingParty::Discover::Service;

use Mouse;
use OpenID::Lite::Constants::Namespace
    qw(SERVER_2_0 SPEC_2_0 SPEC_1_0 SIGNON_2_0);
use List::MoreUtils qw(any none);

has 'uris' => (
    is      => 'rw',
    isa     => 'ArrayRef',
    default => sub { [] },
);

has 'types' => (
    is      => 'rw',
    isa     => 'ArrayRef',
    default => sub { [] },
);

has 'claimed_identifier' => (
    is  => 'rw',
    isa => 'Str',
);

has 'op_local_identifier' => (
    is  => 'rw',
    isa => 'Str',
);

sub copy {
    my $self   = shift;
    my $class  = ref($self);
    my $copied = $class->new;
    my $uris   = $self->uris;
    $copied->add_uri($_) for @$uris;
    my $types = $self->types;
    $copied->add_type($_) for @$types;
    $copied->claimed_identifier( $self->claimed_identifier )
        if $self->claimed_identifier;
    $copied->op_local_identifier( $self->op_local_identifier )
        if $self->op_local_identifier;
    return $copied;
}

sub find_local_identifier {
    my $self = shift;
    return $self->op_local_identifier || $self->claimed_identifier;
}

sub url {
    my $self = shift;
    my $uris = $self->uris;
    return $uris->[0];
}

sub is_op_identifier {
    my $self  = shift;
    my $types = $self->types;
    return ( any { $_ eq SERVER_2_0 } @$types );
}

sub preferred_namespace {
    my $self = shift;
    $self->requires_compatibility_mode ? SPEC_1_0 : SPEC_2_0;
}

sub requires_compatibility_mode {
    my $self  = shift;
    my $types = $self->types;
    return ( none { $_ eq SERVER_2_0 || $_ eq SIGNON_2_0 } @$types );
}

sub add_uri {
    my ( $self, $uri ) = @_;
    my $uris = $self->uris;
    push @$uris, $uri;
}

sub add_uris {
    my $self = shift;
    $self->add_uri($_) for @_;
}

sub add_type {
    my ( $self, $type ) = @_;
    my $types = $self->types;
    push @$types, $type;
}

sub add_types {
    my $self = shift;
    $self->add_type($_) for @_;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

