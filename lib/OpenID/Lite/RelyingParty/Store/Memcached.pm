package OpenID::Lite::RelyingParty::Store::Memcached;

use Mouse;

sub get {
    my ( $self, $key ) = @_;
}

sub set {
    my ( $self, $key, $value ) = @_;
}


no Mouse;
__PACKAGE__->meta->make_immutable;
1;


