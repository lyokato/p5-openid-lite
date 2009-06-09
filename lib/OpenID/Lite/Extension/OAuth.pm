package OpenID::Lite::Extension::OAuth;

use strict;
use warnings;
use base 'Exporter';

our @EXPORT_OK = qw(OAUTH_NS OAUTH_NS_ALIAS);

use constant OAUTH_NS => q{http://specs.openid.net/extensions/oauth/1.0};
use constant OAUTH_NS_ALIAS => q{oauth};

1;

