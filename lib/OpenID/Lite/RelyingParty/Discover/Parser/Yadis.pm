package OpenID::Lite::RelyingParty::Discover::Parser::Yadis;

use Any::Moose;
use OpenID::Lite::Constants::Yadis qw(XRDS_CONTENT_TYPE);

with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::Parser';

use OpenID::Lite::RelyingParty::Discover::Parser::XRDS;
use OpenID::Lite::RelyingParty::Discover::Parser::HTML;

sub parse {
    my ( $self, $result ) = @_;
    my $parser = $self->create_parser_for( $result );
    my $service = $parser->parse( $result )
        or return $self->ERROR( $parser->errstr );
    return $service;
}

sub create_parser_for {
    my ( $self, $result ) = @_;
    my $xrds_regex = quotemeta XRDS_CONTENT_TYPE;
    my $parser
        = ( $result->content_type =~ /^$xrds_regex/i )
        ? OpenID::Lite::RelyingParty::Discover::Parser::XRDS->new
        : OpenID::Lite::RelyingParty::Discover::Parser::HTML->new;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
