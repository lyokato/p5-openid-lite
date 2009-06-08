package OpenID::Lite::Extension::PAPE;

use strict;
use warnings;

use base 'Exporter';

our @EXPORT_OK = qw(
    PAPE_NS
    PAPE_AUTH_MULTIFACTOR_NS
    PAPE_AUTH_MULTIFACTOR_PHYSICAL_NS
    PAPE_AUTH_PHISHING_RESISTANT_NS
    PAPE_NS_ALIAS
);

use constant PAPE_NS => q{http://specs.openid.net/extensions/pape/1.0};
use constant PAPE_AUTH_MULTIFACTOR_NS =>
    q{https://schemas.openid.net/pape/policies/2007/06/multi-factor};
use constant PAPE_AUTH_MULTIFACTOR_PHYSICAL_NS =>
    q{https://schemas.openid.net/pape/policies/2007/06/multi-factor-physical};
use constant PAPE_AUTH_PHISHING_RESISTANT_NS =>
    q{https://schemas.openid.net/pape/policies/2007/06/phishing-resistant};
use constant PAPE_NS_ALIAS => q{pape};

1;

