package OpenID::Lite::RelyingParty::Discover::Method::URL;

use Any::Moose;

use OpenID::Lite::RelyingParty::Discover::Method::Yadis;
use OpenID::Lite::RelyingParty::Discover::Method::HTML;

has '_methods' => (
    is  => 'ro',
    isa => 'ArrayRef',    # OpenID::Lite::RelyingParty::Discoverable composit
    lazy_build => 1,
);

with 'OpenID::Lite::Role::Discoverer';
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';

sub discover {
    my ( $self, $identifier ) = @_;

    # chain of responsibility
    my $methods = $self->_methods;
    for my $method (@$methods) {
        my $services = $method->discover($identifier);
        return $services if $services;
    }

    return $self->ERROR(
        sprintf q{Failed Yadis and HTML discovery for identifier "%s"},
        $identifier );
}

sub _build__methods {
    my $self = shift;
    [   OpenID::Lite::RelyingParty::Discover::Method::Yadis->new(
            agent => $self->agent
        ),
        OpenID::Lite::RelyingParty::Discover::Method::HTML->new(
            agent => $self->agent
        ),
    ];
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
