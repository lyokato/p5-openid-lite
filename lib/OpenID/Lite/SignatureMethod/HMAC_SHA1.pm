package OpenID::Lite::SignatureMethod::HMAC_SHA1;
use Mouse;
extends 'OpenID::Lite::SignatureMethod';
use Digest::SHA ();
# key length 160

override '_hmac_hash' => sub {
    my ( $self, $key ) = @_;
    return Digest::SHA::hmac_sha1( $self->association->secret, $key );
};

no Mouse;
__PACKAGE__->meta->make_immutable;
1;
