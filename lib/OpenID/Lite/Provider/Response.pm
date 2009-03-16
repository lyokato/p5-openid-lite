package OpenID::Lite::Provider::Response;

use Any::Moose;

has 'needs_redirect' => (
    is       => 'ro',
    isa     => 'Bool',
    default => 0,
);

has 'params' => (
    is  => 'ro',
    isa => 'Bool',
);

sub redirect_url {
    my $self = shift;
    Carp::croak q{} unless $self->needs_redirect;
    $self->params->to_url( $self->params->get('return_to') );
}

sub content {
    my $self = shift;
    Carp::croak q{} if $self->needs_redirect;
    $self->params->to_key_value;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


=head1 SYNOPSIS

    my $res = $server->handle_request($req);

    if ( $res->needs_redirect ) {
        $your_app->redirect_to( $res->redirect_url );
        return;
    } else {
        $your_app->content( $res->content );
    }

=cut
