package OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis::HTMLExtractor;

use Any::Moose;
use HTML::TreeBuilder::XPath;
use URI::Escape ();
use OpenID::Lite::Constants::Yadis qw(XRDS_HEADER YADIS_HEADER);

sub extract {
    my ( $self, $content ) = @_;

    my $tree = HTML::TreeBuilder::XPath->new;
    $tree->parse(lc $content);
    my $location
        =  $tree->findvalue( $self->_build_xpath_with( XRDS_HEADER  ) )
        || $tree->findvalue( $self->_build_xpath_with( YADIS_HEADER ) );
    return URI::Escape::uri_unescape($location);
}

sub _build_xpath_with {
    my ( $self, $header ) = @_;
    return sprintf(q{/html/head/meta[@http-equiv='%s']/@content}, lc $header)
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

