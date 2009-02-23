package OpenID::Lite::RelyingParty::Associator::SessionHandler;

use Mouse;
use List::MoreUtils qw(any);

has '_session_type' => (
    is      => 'ro',
    isa     => 'Str',
    default => "",
);

has '_allowed_assoc_types' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [] },
);

# template method
sub set_request_params {
    my ( $self, $service, $params ) = @_;
}

sub match {
    my ( $self, $session_type ) = @_;
    return ( $session_type && $self->_session_type eq $session_type );
}

sub can_handle_assoc_type {
    my ( $self, $assoc_type ) = @_;
    my $allowed = $self->_allowed_assoc_types;
    return ( $assoc_type && ( any { $_ eq $assoc_type } @$allowed ) );
}

# abstract method
sub extract_secret {
    my ( $self, $params ) = @_;
    die "abstract method.";
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;


