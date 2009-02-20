package OpenID::Lite::RelyingParty::IDResHandler::SignatureVerifier::Association;

use Mouse;
with 'OpenID::Lite::Role::ErrorHandler';

use OpenID::Lite::SignatureMethod::Factory;

sub verify {
    my ( $self, $params ) = @_;
    my $sig = $params->get('sig');
    return $self->ERROR() unless $sig;

    my $factory = OpenID::Lite::SignatureMethod::Factory->new;
    my $method = $factory->create_signature_method( $self->association );
    $sig eq $method->sign($params);
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

