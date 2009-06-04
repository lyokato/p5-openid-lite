package OpenID::Lite::Provider::Response;

use Any::Moose;

has 'type' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'params' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::Message',
    required => 1,
);

has 'should_be_signed' => (
    is      => 'ro',
    isa     => 'Bool',
    default => 0,
);

sub is_for_redirect {
    my $self = shift;
}

sub is_for_setup {
    my $self = shift;
}

sub add_extension {
    my ( $self, $extension ) = @_;
    $extension->append_to_params( $self->params );
}

sub redirect_url {
    my $self = shift;
    Carp::croak q{} unless $self->is_for_redirect;
    $self->params->to_url( $self->params->get('return_to') );
}

sub content {
    my $self = shift;
    Carp::croak q{} if $self->is_for_redirect || $self->is_for_setup;
    $self->params->to_key_value;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

=head1 SYNOPSIS

=cut
