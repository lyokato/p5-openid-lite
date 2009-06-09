package OpenID::Lite::Extension::Request;

use Any::Moose;

# called from provider-side
sub from_request {
    my ( $self, $request ) = @_;
}

# called from relying party side
sub append_to_params {
    my ( $self, $params ) = @_;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


