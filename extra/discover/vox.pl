#!/usr/bin/perl 

use strict;
use warnings;

use lib '../../lib';
use OpenID::Lite::RelyingParty::Discover;
use OpenID::Lite::Identifier;
use Data::Dump qw(dump);
use Perl6::Say;
use OpenID::Lite::Agent::Dump;

#my $identifier = q{https://www.google.com/accounts/o8/id};
my $identifier = q{lyokato.vox.com};
my $id = OpenID::Lite::Identifier->normalize($identifier);
my $disco = OpenID::Lite::RelyingParty::Discover->new(
#agent=>OpenID::Lite::Agent::Dump->new
);
my $servers = $disco->discover($id)
    or die $disco->errstr;
say dump($servers);
