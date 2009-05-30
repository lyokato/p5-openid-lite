use strict;
use warnings;

use Test::More tests => 12;
use OpenID::Lite::Util::XRI;


is(q{xri}, OpenID::Lite::Util::XRI->identifier_scheme('=john.smith'));
is(q{xri}, OpenID::Lite::Util::XRI->identifier_scheme('@smith/john'));
is(q{xri}, OpenID::Lite::Util::XRI->identifier_scheme('xri://=john'));
is(q{xri}, OpenID::Lite::Util::XRI->identifier_scheme('@ootao*test1'));
is(q{uri}, OpenID::Lite::Util::XRI->identifier_scheme('smoker.myopenid.com'));
is(q{uri}, OpenID::Lite::Util::XRI->identifier_scheme('http://smoker.myopenid.com'));
is(q{uri}, OpenID::Lite::Util::XRI->identifier_scheme('https://smoker.myopenid.com'));

is(q{@example/abc%252Fd/ef}, OpenID::Lite::Util::XRI->escape_for_iri('@example/abc%2Fd/ef'));
is(q{@example/foo/(@bar)}, OpenID::Lite::Util::XRI->escape_for_iri('@example/foo/(@bar)'), q{no escapes});
is(q{@example/foo/(@bar%2Fbuz)}, OpenID::Lite::Util::XRI->escape_for_iri('@example/foo/(@bar/buz)'), q{escape slashes});

is(q{@example/foo/(@buz%3Fp=q%23r)?i=j#k},
    OpenID::Lite::Util::XRI->escape_for_iri('@example/foo/(@buz?p=q#r)?i=j#k'), q{escape query and fragment});

is(q{xri://@example}, OpenID::Lite::Util::XRI->to_iri_normal('@example'));
