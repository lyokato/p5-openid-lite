package OpenID::Lite::SignatureMethod::Factory;

use Mouse;

use OpenID::Lite::SignatureMethod::HMAC_SHA1;
use OpenID::Lite::SignatureMethod::HMAC_SHA256;
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);

sub create_signature_method {
    my ( $self, $association ) = @_;
    if ( $association->type eq HMAC_SHA1 ) {
        return OpenID::Lite::SignatureMethod::HMAC_SHA1->new(
            association => $association, );
    }
    elsif ( $association->type eq HMAC_SHA256 ) {
        return OpenID::Lite::SignatureMethod::HMAC_SHA256->new(
            association => $association, );
    }
    return;

}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;
