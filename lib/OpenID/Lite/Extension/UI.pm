package OpenID::Lite::Extension::UI;

use strict;
use warnings;
use base 'Exporter';

our @EXPORT_OK = qw(UI_NS UI_POPUP_NS UI_LANG_NS UI_NS_ALIAS);

use constant UI_NS       => q{http://specs.openid.net/extensions/ui/1.0};
use constant UI_POPUP_NS => q{http://specs.openid.net/extensions/ui/1.0/popup};
use constant UI_LANG_NS  => q{http://specs.openid.net/extensions/ui/1.0/lang-pref};
use constant UI_NS_ALIAS => q{ui};

1;
