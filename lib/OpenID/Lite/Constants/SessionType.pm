package OpenID::Lite::Constants::SessionType;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = ( all => [qw(NO_ENCRYPTION DH_SHA1 DH_SHA256)] );
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant NO_ENCRYPTION => 'no-encryption';
use constant DH_SHA1       => 'DH-SHA1';
use constant DH_SHA256     => 'DH-SHA256';

1;

