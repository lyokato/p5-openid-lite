package OpenID::Lite::Constants::Namespace;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = (
    all => [
        qw(
            SPEC_2_0
            SPEC_1_0
            XRDS
            XRD_2_0
            SERVER_2_0
            SIGNON_2_0
            SIGNON_1_1
            SIGNON_1_0
            IDENTIFIER_SELECT
            RETURN_TO
            )
    ]
);
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant SPEC_2_0   => q{http://specs.openid.net/auth/2.0};
use constant SPEC_1_0   => q{http://openid.net/xmlns/1.0};
use constant XRDS       => q{xri://$xrds};
use constant XRD_2_0    => q{xri://$xrd*($v*2.0)};
use constant SERVER_2_0 => q{http://specs.openid.net/auth/2.0/server};
use constant SIGNON_2_0 => q{http://specs.openid.net/auth/2.0/signon};
use constant SIGNON_1_1 => q{http://openid.net/signon/1.1};
use constant SIGNON_1_0 => q{http://openid.net/signon/1.0};

use constant IDENTIFIER_SELECT =>
    q{http://specs.openid.net/auth/2.0/identifier_select};

use constant RETURN_TO => q{http://specs.openid.net/auth/2.0/return_to};

1;

