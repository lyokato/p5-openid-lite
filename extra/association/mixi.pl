#!/usr/bin/perl;

use strict;
use warnings;

use lib '../../lib';

use OpenID::Lite::RelyingParty::Discover::Service;
use OpenID::Lite::RelyingParty::Discover;
use OpenID::Lite::Identifier;
use OpenID::Lite::RelyingParty::Associator;
use OpenID::Lite::RelyingParty::Associator::ParamBuilder;
use OpenID::Lite::Constants::AssocType qw(:all);
use OpenID::Lite::Constants::SessionType qw(:all);
use OpenID::Lite::RelyingParty::CheckID::Request;
use OpenID::Lite::Extension::SREG::Request;
use OpenID::Lite::Agent::Dump;

use Data::Dump qw(dump);
use Perl6::Say;
use MIME::Base64;

my $service = OpenID::Lite::RelyingParty::Discover::Service->new(
    types => [
          "http://specs.openid.net/auth/2.0/server",
          "http://openid.net/sreg/1.0",
          "http://openid.net/extensions/sreg/1.1",
          "http://openid.net/srv/ax/1.0",
        ],
    uris => ["https://mixi.jp/openid_server.pl"],
);
my $assoc = OpenID::Lite::RelyingParty::Associator->new(
    assoc_type => HMAC_SHA1,
    session_type => NO_ENCRYPTION,
    #session_type => DH_SHA1,
    agent => OpenID::Lite::Agent::Dump->new,
);
my $association = $assoc->associate($service)
    or die $assoc->errstr;

say sprintf q{ASSOC_TYPE:   %s}, $association->type;
say sprintf q{ASSOC_HANDLE: %s}, $association->handle;
say sprintf q{EXPIRATION:   %s}, $association->expires_at;
say sprintf q{SECRET:       %s}, MIME::Base64::encode_base64($association->secret);

my $req = OpenID::Lite::RelyingParty::CheckID::Request->new(
    service     => $service,
    association => $association,
);

my $sreg = OpenID::Lite::Extension::SREG::Request->new;
$sreg->request_field('nickname');

use Data::Dump qw(dump);
warn dump($sreg);
$req->add_extension($sreg);

my $url = $req->redirect_url(
    realm     => q{http://example.com},
    return_to => q{http://example.com/return_to},
);
say $url;
