use strict;

use Test::More tests => 2;

use XML::LibXML::XPathContext;
use OpenID::Lite::Identifier;
use OpenID::Lite::RelyingParty::Discover::Fetcher::XRI;

my $identify = OpenID::Lite::Identifier->normalize(q{=zigorou});
my $fetcher = OpenID::Lite::RelyingParty::Discover::Fetcher::XRI->new;
my $xrds = $fetcher->fetch($identify->as_string);
my @services = $xrds->findnodes(q{*[local-name()='XRDS']/*[local-name()='XRD']});
my @cids = $services[0]->findnodes(q{*[local-name()='CanonicalID']});
my $cid = $cids[0]->findvalue(q{text()});
is(scalar @services, "");
is(scalar @cids, "");
is($cid, "");
is($xrds->toString, "");
