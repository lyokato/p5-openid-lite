package OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis::HTMLExtractor;

use HTML::TreeBuilder::XPath;
use URI::Escape ();
use OpenID::Lite::Constants::Yadis qw(XRDS_HEADER YADIS_HEADER);

sub extract {
    my ( $class, $content ) = @_;

    my $tree = HTML::TreeBuilder::XPath->new;
    $tree->parse(lc $content);
    my $location
        =  $tree->findvalue( $class->_build_xpath_with( XRDS_HEADER  ) )
        || $tree->findvalue( $class->_build_xpath_with( YADIS_HEADER ) );
    return unless $location;
    return URI::Escape::uri_unescape($location);
}

sub _build_xpath_with {
    my ( $class, $header ) = @_;
    return sprintf(q{/html/head/meta[@http-equiv='%s']/@content}, lc $header)
}

1;

