package OpenID::Lite::Provider::Discover::Parser;

use Any::Moose;
use XML::LibXML;
use OpenID::Lite::Constants::Namespace qw(RETURN_TO);
with 'OpenID::Lite::Role::ErrorHandler';

sub parse {
    my ( $self, $result ) = @_;

    my $parser = XML::LibXML->new;
    my $doc;
    eval { $doc = $parser->parse_string( $result->content ); };
    if ($@) {
        return $self->ERROR( sprintf q{Failed to parse xrds "%s"}, $@ );
    }

    my @xrd
        = $doc->findnodes(q{*[local-name()='XRDS']/*[local-name()='XRD']});
    return $self->ERROR( q{XRD element not found} )
        unless @xrd > 0;

    my $xrd = $xrd[0];
    my @service_nodes = $xrd->findnodes(q{*[local-name()='Service']});
    for my $service_node ( @service_nodes ) {
        my $urls = $self->_find_return_to($service_node);
        return $urls if $urls;
    }
    return $self->ERROR(q{return_to not found.});
}

sub _find_return_to {
    my ( $self, $service_elem ) = @_;

    my @type_nodes = $service_elem->findnodes(q{*[local-name()='Type']});
    my @types = grep {
        my $t = $_->findvalue(q{text()});
        return ($t && $t eq RETURN_TO)
    } @type_nodes;

    return unless @types > 0;

    my @uri_nodes = $service_elem->findnodes(q{*[local-name()='URI']});

    # Schwartzian transform
    my @uris = map { $_->[0] }
        sort { $a->[1] <=> $b->[1] }
        map {
        [ $_->findvalue(q{text()}), $_->findvalue(q{@priority}) || 100 ]
        } @uri_nodes;

    #my @uris = map { $_->findvalue(q{text()}) }
    #    sort {
    #    ( $a->findvalue(q{@priority}) || 100 )
    #        <=> ( $b->findvalue(q{@priority}) || 100 )
    #    } @uri_nodes;

    return unless @uris > 0;
    return \@uris;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

