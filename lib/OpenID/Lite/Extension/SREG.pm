package OpenID::Lite::Extension::SREG;

use strict;
use warnings;
use base 'Exporter';

our @EXPORT_OK = qw(SREG_NS_1_0 SREG_NS_1_1 SREG_NS_ALIAS);

use constant SREG_NS_1_0   => q{http://openid.net/sreg/1.0};
use constant SREG_NS_1_1   => q{http://openid.net/extensions/sreg/1.1};
use constant SREG_NS_ALIAS => q{sreg};

1;


