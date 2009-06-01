use strict;
use warnings;

use Test::More tests => 1;                      # last test to print

use OpenID::Lite::RelyingParty::Store::OnMemory;

my $mstore = OpenID::Lite::RelyingParty::Store::OnMemory->new;
is('', '');


