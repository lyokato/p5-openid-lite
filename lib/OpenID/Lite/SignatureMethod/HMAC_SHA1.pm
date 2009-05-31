package OpenID::Lite::SignatureMethod::HMAC_SHA1;
use Any::Moose;
extends 'OpenID::Lite::SignatureMethod';
use Digest::SHA ();
# key length 160

override '_hmac_hash' => sub {
    my ( $self, $secret, $key ) = @_;
    return Digest::SHA::hmac_sha1( $key, $secret );
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
