package OpenID::Lite::RelyingParty::Discover::Parser::XRDS;

use Any::Moose;
with 'OpenID::Lite::Role::Parser';
with 'OpenID::Lite::Role::ErrorHandler';

use XML::LibXML;
use OpenID::Lite::RelyingParty::Discover::Service::Builder;

sub parse {
    my ( $self, $result ) = @_;

    my $identifier = $result->normalized_identifier;
    my $parser     = XML::LibXML->new;
    my $doc;
    eval { $doc = $parser->parse_string( $result->content ); };
    if ($@) {
        return $self->ERROR( sprintf q{Failed to parse xrds "%s"}, $@ );
    }

    my @xrd
        = $doc->findnodes(q{*[local-name()='XRDS']/*[local-name()='XRD']});
    return $self->ERROR( sprintf q{XRD element not found for iname "%s".},
        $identifier )
        unless @xrd > 0;

    my $xrd = $xrd[0];

    my $builder = OpenID::Lite::RelyingParty::Discover::Service::Builder->new(
        claimed_identifier => $identifier, );
    my $services = $builder->build_services($xrd);
    return $self->ERROR(q{No service found.}) unless @$services > 0;
    return $services;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

