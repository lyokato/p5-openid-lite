package OpenID::Lite::Provider::Discover;

use Any::Moose;
use OpenID::Lite::Provider::Discover::Parser;
use OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis;
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::ErrorHandler';

has '_fetcher' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_parser' => (
    is         => 'ro',
    lazy_build => 1,
);

sub discover {
    my ( $self, $rp_realm_url, $not_allow_redirection ) = @_;

    my $result = $self->_fetcher->fetch($rp_realm_url)
        or return $self->ERROR( $self->_fetcher->errstr );

    # when discovery is carried out for validating realm,
    # must not allow redirection.
    return $self->ERROR(q{redirected.})
        if ( $not_allow_redirection && $rp_realm_url ne $result->final_url );

    my $return_to_urls = $self->_parser->parse($result)
        or return $self->ERROR( $self->_parser->errstr );
    return $return_to_urls;

}

sub _build__fetcher {
    my $self    = shift;
    my $fetcher = OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis->new(
        agent => $self->agent );
    return $fetcher;
}

sub _build__parser {
    my $self   = shift;
    my $parser = OpenID::Lite::Provider::Discover::Parser->new;
    return $parser;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

