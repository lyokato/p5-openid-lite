package OpenID::Lite::Extension;

use Any::Moose;

sub append_params {
    my ( $self, $params ) = @_;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
