package OpenID::Lite::Extension::Response;

use Any::Moose;

# called from provider-side
sub extract_response {

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


