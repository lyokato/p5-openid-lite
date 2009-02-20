package OpenID::Lite::Constants::AssocType;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = ( all => [qw(HMAC_SHA1 HMAC_SHA256)] );
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant HMAC_SHA1   => 'HMAC-SHA1';
use constant HMAC_SHA256 => 'HMAC-SHA256';

1;

