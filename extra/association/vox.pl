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

my $identifier = q{lyokato.vox.com};
my $id = OpenID::Lite::Identifier->normalize($identifier);
my $disco = OpenID::Lite::RelyingParty::Discover->new(
#agent=>OpenID::Lite::Agent::Dump->new
);
my $servers = $disco->discover($id)
    or die $disco->errstr;
say dump($servers);

my $service = $servers->[0];

my $assoc = OpenID::Lite::RelyingParty::Associator->new(
    assoc_type => HMAC_SHA256,
    #assoc_type   => HMAC_SHA1,
    #session_type => NO_ENCRYPTION,
    #session_type => DH_SHA1,
    session_type => DH_SHA256,
);
my $association = $assoc->associate($service)
    or die $assoc->errstr;

say sprintf q{ASSOC_TYPE:   %s}, $association->type;
say sprintf q{ASSOC_HANDLE: %s}, $association->handle;
say sprintf q{EXPIRATION:   %s}, $association->expires_at;
say sprintf q{SECRET:       %s},
    MIME::Base64::encode_base64( $association->secret );

my $req = OpenID::Lite::RelyingParty::CheckID::Request->new(
    service     => $service,
    association => $association,
);

my $url = $req->redirect_url(
    realm     => q{http://example.com/},
    return_to => q{http://example.com/return_to},
);
say $url;
