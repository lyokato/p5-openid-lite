use strict;
use Test::More tests => 13;
BEGIN { 
    # core
    use_ok('OpenID::Lite');
    use_ok('OpenID::Lite::Message');
    use_ok('OpenID::Lite::Identifier');

    # constants
    use_ok('OpenID::Lite::Constants::AssocType');
    use_ok('OpenID::Lite::Constants::SessionType');
    use_ok('OpenID::Lite::Constants::ModeType');
    use_ok('OpenID::Lite::Constants::Namespace');

    # relyingparty

    # discovery
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::XRI');
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::HTML');
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::Yadis');
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::URL');

    use_ok('OpenID::Lite::RelyingParty::Discover');

    # association
    use_ok('OpenID::Lite::RelyingParty::Associator');

    #use_ok('OpenID::Lite::RelyingParty');
};



