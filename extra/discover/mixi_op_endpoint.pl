#!/usr/bin/perl 

use strict;
use warnings;

use lib '../../lib';
use OpenID::Lite::RelyingParty::Discover;
use OpenID::Lite::Identifier;
use Data::Dump qw(dump);
use Perl6::Say;
use OpenID::Lite::Agent::Dump;

my $identifier = q{mixi.jp};
my $id = OpenID::Lite::Identifier->normalize($identifier);
my $disco = OpenID::Lite::RelyingParty::Discover->new( agent => OpenID::Lite::Agent::Dump->new );
my $servers = $disco->discover($id);
say dump($servers);
