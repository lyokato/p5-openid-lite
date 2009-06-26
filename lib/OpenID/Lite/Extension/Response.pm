package OpenID::Lite::Extension::Response;

use Any::Moose;

sub extract_response {
    my ( $class, $ext_req, $data ) = @_;
}

# called from relying-party side
sub from_success_response {

}

sub append_to_params {
    my ( $self, $params ) = @_;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


