package OpenID::Lite::SignatureMethod::HMAC_SHA256;
use Any::Moose;
extends 'OpenID::Lite::SignatureMethod';
use Digest::SHA ();
# key length 256

override '_hmac_hash' => sub {
    my ( $self, $secret, $key ) = @_;
    return Digest::SHA::hmac_sha256( $secret, $key );
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

