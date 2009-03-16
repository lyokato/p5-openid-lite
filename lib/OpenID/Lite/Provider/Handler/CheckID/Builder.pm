package OpenID::Lite::Provider::Handler::CheckID::Builder;

use Any::Moose;
with 'OpenID::Lite::Role::ErrorHandler';

use OpenID::Lite::Provider::Handler::CheckID;

sub build_from_params {
    my ( $self, $params ) = @_;
    my $mode = $params->get('mode');
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


