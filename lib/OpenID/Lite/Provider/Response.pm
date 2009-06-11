package OpenID::Lite::Provider::Response;

use Any::Moose;
use OpenID::Lite::Constants::ProviderResponseType qw(:all);

has 'type' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'req_params' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::Message',
    required => 1,
);

has 'res_params' => (
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
    return $self->type eq REDIRECT;
}

sub is_for_setup {
    my $self = shift;
    return $self->type eq SETUP;
}

sub is_for_direct {
    my $self = shift;
    return $self->type eq DIRECT;
}

sub add_extension {
    my ( $self, $extension ) = @_;
    $extension->append_to_params( $self->res_params );
}

sub redirect_url {
    my $self = shift;
    confess
        q{redirect_url shouldn't be called when the resopnse is not for redirect}
        unless $self->is_for_redirect;
    return $self->res_params->to_url( $self->res_params->get('return_to') );
}

sub content {
    my $self = shift;
    confess
        q{content shouldn't be called when the response is for redirect or setup}
        if $self->is_for_redirect || $self->is_for_setup;
    return $self->res_params->to_key_value;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
