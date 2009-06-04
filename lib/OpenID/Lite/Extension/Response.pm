package OpenID::Lite::Extension::Response;

use Any::Moose;

sub append_to_params {
    my ( $self, $params ) = @_;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


