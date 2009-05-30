package OpenID::Lite::RelyingParty::Discover::Parser::XRI;

use Any::Moose;
with 'OpenID::Lite::Role::Parser';
with 'OpenID::Lite::Role::ErrorHandler';

use OpenID::Lite::Util::XRI;
use OpenID::Lite::RelyingParty::Discover::Service::Builder;

sub parse {
    my ( $self, $result ) = @_;

    my $identifier = $result->normalized_identifier;
    my $doc        = $result->xrds;

    my @xrd
        = $doc->findnodes(q{*[local-name()='XRDS']/*[local-name()='XRD']});
    return $self->ERROR( sprintf q{XRD element not found for iname "%s".},
        $identifier )
        unless @xrd > 0;

    @xrd = reverse @xrd;
    my $last_xrd = shift @xrd;

    my $canonical_id = $self->_get_canonical_id($last_xrd)
        or return $self->ERROR( sprintf q{No CanonicalID found for XRI "%s".},
        $identifier );

    $self->_validate_canonical_id( \@xrd, $canonical_id, $identifier )
        or return $self->ERROR( sprintf q{Invalid XRDS for XRI "%s".},
        $identifier );

    my $builder = OpenID::Lite::RelyingParty::Discover::Service::Builder->new(
        claimed_identifier => $canonical_id, );

    my $services = $builder->build_services($last_xrd);
    return $self->ERROR(q{No service found.}) unless @$services > 0;
    return $services;
}

sub _validate_canonical_id {
    my ( $self, $xrd_list, $canonical_id, $iname ) = @_;
    my $child_id = lc $canonical_id;
    for my $xrd ( @$xrd_list ) {
        my $parent_sought = substr($child_id, rindex($child_id, '!'));
        my @cids = $xrd->findnodes(q{*[local-name()='CanonicalID']});
        return 0 unless @cids > 0;
        my $cid = $cids[0];
        my $parent
            = OpenID::Lite::Util::XRI->make_xri( $cid->findvalue(q{text()}) );
        return 0 unless $parent;
        return 0 if ($parent_sought ne lc $parent);
        $child_id = $parent_sought;
    }

    my $root = OpenID::Lite::Util::XRI->root_authority($iname);
    return 0 unless
        OpenID::Lite::Util::XRI->provider_is_authoritative($root, $child_id);
    1;
}

sub _get_canonical_id {
    my ( $self, $xrd ) = @_;

    my @cids = $xrd->findnodes(q{*[local-name()='CanonicalID']});
    return unless @cids > 0;

    my $cid = $cids[0];
    my $canonical_id
        = OpenID::Lite::Util::XRI->make_xri( $cid->findvalue(q{text()}) );

    return $canonical_id;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

