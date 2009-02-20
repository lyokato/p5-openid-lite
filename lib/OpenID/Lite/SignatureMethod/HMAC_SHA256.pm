package OpenID::Lite::SignatureMethod::HMAC_SHA256;
use Mouse;
extends 'OpenID::Lite::SignatureMethod';
# key length 256

override '_hmac_hash' => sub {
    my ( $self, $key ) = @_;
    return Digest::SHA::hmac_sha256( $self->association->secret, $key );
};

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

