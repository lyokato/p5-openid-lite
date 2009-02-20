package OpenID::Lite::Test::RelyingParty::Discover::XRIDiscovery;
use base qw(Test::Class);
use Test::More;

use OpenID::Lite::RelyingParty::Discover::Method::XRI;

sub make_fixtre : Test(setup) {
    my $self = shift;
    $self->{discoverer}
        = OpenID::Lite::RelyingParty::Discover::Method::XRI->new(
            agent => $self->agent 
        );
}

sub test_discover : Test {
    my $self = shift;
    my $info = $discoverer->discover();
}

1;
