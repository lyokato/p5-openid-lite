package OpenID::Lite::Extension::Request;

use Any::Moose;

sub from_request {
    my ( $self, $request ) = @_;
}

sub append_to_params {
    my ( $self, $params ) = @_;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


