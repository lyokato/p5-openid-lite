package OpenID::Lite::SignatureMethods;

use strict;
use warnings;

use OpenID::Lite::Constants::AssocType qw(:all);
use OpenID::Lite::SignatureMethod::HMAC_SHA1;
use OpenID::Lite::SignatureMethod::HMAC_SHA256;

my %methods = (
    HMAC_SHA1()   => OpenID::Lite::SignatureMethod::HMAC_SHA1->new,
    HMAC_SHA256() => OpenID::Lite::SignatureMethod::HMAC_SHA256->new,
);

sub select_method {
    my ( $self, $type ) = @_;
    return $methods{$type};
}

1;

