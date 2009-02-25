package OpenID::Lite::Extension;

use Mouse;

sub append_params {
    my ( $self, $params ) = @_;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;
