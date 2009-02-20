package OpenID::Lite::RelyingParty::Store::Null;

use Mouse;
with 'OpenID::Lite::Role::Storable';

sub get {
    my ( $self, $key ) = @_;
    return;
}

sub set {
    my ( $self, $key, $value ) = @_;
    return;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;
