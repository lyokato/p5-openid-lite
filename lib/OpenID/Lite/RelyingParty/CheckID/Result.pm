package OpenID::Lite::RelyingParty::CheckID::Result;

use Any::Moose;
use OpenID::Lite::Constants::CheckIDResponse qw(:all);

has 'type' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'message' => (
    is      => 'ro',
    isa     => 'Str',
    default => '',
);

# used under error status
has 'contact' => ();
has 'reference' => ();


# used under setup_needed status
has 'url' => (
    is  => 'ro',
    isa => 'Str',
    predicate => 'has_url',
);

sub is_invalid {
    my $self = shift;
    return $self->type eq IS_INVALID;
}

sub is_error {
    my $self = shift;
    return $self->type eq IS_ERROR;
}

sub is_canceled {
    my $self = shift;
    return $self->type eq IS_CANCELED;
}

sub is_setup_needed {
    my $self = shift;
    return $self->type eq IS_SETUP_NEEDED;
}

sub is_success {
    my $self = shift;
    return $self->type eq IS_SUCCESS;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

