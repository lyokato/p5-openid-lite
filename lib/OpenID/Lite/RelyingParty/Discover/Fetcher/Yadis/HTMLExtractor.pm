package OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis::HTMLExtractor;

use Mouse;
use HTML::TreeBuilder::XPath;
use URI::Escape ();
use OpenID::Lite::Constants::Yadis qw(XRDS_HEADER YADIS_HEADER);

sub extract {
    my ( $self, $content ) = @_;

    my $tree = HTML::TreeBuilder::XPath->new;
    $tree->parse(lc $content);
    my $location
        = $tree->findvalue(
        sprintf q{/html/head/meta[@http-equiv='%s']/@content},
        lc XRDS_HEADER )
        || $tree->findvalue(
        sprintf q{/html/head/meta[@http-equiv='%s']/@content},
        lc YADIS_HEADER );
    return URI::Escape::uri_unescape($location);
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

