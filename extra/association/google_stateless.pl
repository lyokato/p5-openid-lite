#!/usr/bin/perl;

use strict;
use warnings;

use lib '../../lib';

use OpenID::Lite::RelyingParty::Discover::Service;
use OpenID::Lite::RelyingParty::Discover;
use OpenID::Lite::Identifier;
use OpenID::Lite::RelyingParty::Associator;
use OpenID::Lite::RelyingParty::Associator::ParamBuilder;
use OpenID::Lite::RelyingParty::Associator;
use OpenID::Lite::Constants::AssocType qw(:all);
use OpenID::Lite::Constants::SessionType qw(:all);
use OpenID::Lite::RelyingParty::CheckID::Request;

use Data::Dump qw(dump);
use Perl6::Say;
use MIME::Base64;

my $service = OpenID::Lite::RelyingParty::Discover::Service->new(
    types => [
        "http://specs.openid.net/auth/2.0/server",
        "http://openid.net/srv/ax/1.0",
    ],
    uris => ["https://www.google.com/accounts/o8/ud?source=gmail"],
);

my $req = OpenID::Lite::RelyingParty::CheckID::Request->new(
    service => $service,
);

my $url = $req->redirect_url(
    realm     => q{http://example.com/},
    return_to => q{http://example.com/return_to},
);
say $url;
