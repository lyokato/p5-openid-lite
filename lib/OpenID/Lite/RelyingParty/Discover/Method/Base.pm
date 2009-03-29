package OpenID::Lite::RelyingParty::Discover::Method::Base;

use Any::Moose;
with 'OpenID::Lite::Role::Discoverer';
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';

has '_fetcher' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_parser' => (
    is         => 'ro',
    lazy_build => 1,
);

sub discover {
    my ( $self, $identifier ) = @_;
    my $result = $self->_fetcher->fetch( $identifier->as_string )
        or return $self->ERROR( $self->_fetcher->errstr );
    my $services = $self->_parser->parse( $result )
        or return $self->ERROR( $self->_parser->errstr );
    return $services;
}

sub _build__fetcher {
    die "Abstract Method";
}


sub _build__parser {
    die "Abstract Method";
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


