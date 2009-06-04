package OpenID::Lite::SignatureMethod::HMAC_SHA256;
use Any::Moose;
extends 'OpenID::Lite::SignatureMethod';
use Digest::SHA ();
# key length 256

override 'hmac_hash' => sub {
    my ( $self, $secret, $key ) = @_;
    return Digest::SHA::hmac_sha256( $key, $secret );
};

override 'hmac_hash_hex' => sub {
    my ( $self, $secret, $key ) = @_;
    return Digest::SHA::hmac_sha256_hex( $key, $secret );
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

