package OpenID::Lite::Test::DirectCommunication::Dummy;

use Mouse;
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::ErrorHandler';

sub send_request {
    my ( $self, $url, $params ) = @_;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;


