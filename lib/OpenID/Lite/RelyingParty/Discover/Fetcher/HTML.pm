package OpenID::Lite::RelyingParty::Discover::Fetcher::HTML;

use Any::Moose;
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::ErrorHandler';

use OpenID::Lite::RelyingParty::Discover::FetchResult;

sub fetch {
    my ( $self, $uri ) = @_;

    my $res = $self->agent->get($uri);
    return $self->ERROR(
        sprintf q{Failed to HTML based discovery for url "%s"}, $uri )
        unless $res->is_success;

    my $result = OpenID::Lite::RelyingParty::Discover::FetchResult->new;
    $result->final_url( $res->base->as_string );
    $result->normalized_identifier( $uri );
    $result->content_type( lc $res->header('Content-Type') );
    $result->content( $res->content );

    return $result;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

