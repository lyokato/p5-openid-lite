package OpenID::Lite::RelyingParty::Discover::Parser::HTML;

use Any::Moose;
with 'OpenID::Lite::Role::Parser';
with 'OpenID::Lite::Role::ErrorHandler';

use OpenID::Lite::RelyingParty::Discover::Service;
use OpenID::Lite::Constants::Namespace qw(SIGNON_2_0 SIGNON_1_1);
use HTML::TreeBuilder::XPath;

sub parse {
    my ( $self, $result ) = @_;

    my $rels = [
        {   namespace    => SIGNON_2_0,
            endpoint_rel => q{openid2.provider},
            local_id_rel => q{openid2.local_id},
        },
        {   namespace    => SIGNON_1_1,
            endpoint_rel => q{openid.server},
            local_id_rel => q{openid.delegate},

        },
    ];

    my $tree = HTML::TreeBuilder::XPath->new;
    $tree->parse( lc $result->content );

    my $services = [];
    for my $rel (@$rels) {
        my $service = $self->_extract( $tree, $rel );
        if ($service) {
            $service->claimed_identifier( $result->normalized_identifier );
            push @$services, $service;
        }
    }

    return $self->ERROR(
        q{Couldn't extract provider information for OpenID protocol})
        unless @$services > 0;

    return $services;

}

sub _extract {
    my ( $self, $tree, $rel ) = @_;
    my $op_endpoint_url
        = $tree->findvalue( $self->_build_xpath_with( $rel->{endpoint_rel} ) )
        or return;

    my $service = OpenID::Lite::RelyingParty::Discover::Service->new;
    $service->add_uri($op_endpoint_url);
    $service->add_type( $rel->{namespace} );
    my $local_id
        = $tree->findvalue( $self->_build_xpath_with( $rel->{local_id_rel} ) );
    $service->op_local_identifier($local_id) if $local_id;
    return $service;
}

sub _build_xpath_with {
    my ( $self, $rel ) = @_;
    return sprintf(q{/html/head/link[@rel="%s"][1]/@href}, $rel);
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

