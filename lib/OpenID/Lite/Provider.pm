package OpenID::Lite::Provider;

use Any::Moose;
use OpenID::Lite::Message;
use OpenID::Lite::Realm;
use OpenID::Lite::Provider::Discover;
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';

has '_discoverer' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::Provider::Discover',
    lazy_build => 1,
);

sub handle_request {
    my ( $self, $request ) = @_;
    my $params = OpenID::Lite::Message->from_request($request);
}

sub make_rp_login_assertion_with_realm {
    my ( $self, $rp_realm ) = @_;
    my $urls = $self->discover_rp($rp_realm)
        or return;
    return $self->ERROR( sprintf q{url not found for realm, "%s"}, $rp_realm )
        unless @$urls > 0;
    return $self->make_rp_login_assertion( $urls->[0] );
}

sub make_rp_login_assertion {
    my ( $self, $url ) = @_;
}

sub discover_rp {
    my ( $self, $rp_realm ) = @_;
    unless ( ref($rp_realm) eq 'OpenID::Lite::Realm' ) {
        $rp_realm = OpenID::Lite::Realm->parse($rp_realm)
            or
            return $self->ERROR( sprintf q{Invalid realm "%s"}, $rp_realm );
    }
    my $return_to_urls
        = $self->_discoverer->discover( $rp_realm->build_discovery_url )
        or return $self->ERROR( $self->_discover->errstr );
    return $return_to_urls;
}

sub _build__discoverer {
    my $self = shift;
    return OpenID::Lite::Provider::Discover->new( agent => $self->agent );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

