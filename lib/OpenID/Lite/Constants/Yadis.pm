package OpenID::Lite::Constants::Yadis;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS
    = ( all => [qw(XRDS_HEADER YADIS_HEADER XRDS_CONTENT_TYPE)] );
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant XRDS_HEADER       => q{X-XRDS-Location};
use constant YADIS_HEADER      => q{X-Yadis-Location};
use constant XRDS_CONTENT_TYPE => q{application/xrds+xml};

1;

