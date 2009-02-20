package OpenID::Lite::Provider;

use Mouse;

sub validate_request {
    my ($self, %params) = @_;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;


