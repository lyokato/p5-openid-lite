package OpenID::Lite::Extension::PAPE::Response;

use Any::Moose;
extends 'OpenID::Lite::Extension::Response';

sub from_success_response {
    my ( $class, $result ) = @_;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

