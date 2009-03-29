package OpenID::Lite::RelyingParty::IDResHandler::SignatureVerifier::Association;

use Any::Moose;
with 'OpenID::Lite::Role::ErrorHandler';

use OpenID::Lite::SignatureMethods;

sub verify {
    my ( $self, $params ) = @_;
    my $sig = $params->get('sig');
    return $self->ERROR(q{}) unless $sig;

    my $method = OpenID::Lite::SignatureMethods->select_method( $self->association->type );
    return $method->verify( $self->association->secret, $params, $sig );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

