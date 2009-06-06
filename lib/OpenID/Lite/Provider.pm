package OpenID::Lite::Provider;

use Any::Moose;
use OpenID::Lite::Message;
use OpenID::Lite::Realm;
use OpenID::Lite::Provider::Discover;
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';

has '_discover' => (
    is         => 'ro',
    lazy_build => 1,
);

sub handle_request {
    my ( $self, $request ) = @_;
    my $req_params = $self->_build_request_params($request);
}

sub _build_request_params {
    my ( $self, $request ) = @_;
    my $params = OpenID::Lite::Message->from_request($request);
    return $params;
}

sub discover_rp {
    my ( $self, $rp_realm ) = @_;
    unless ( ref($rp_realm) eq 'OpenID::Lite::Realm' ) {
        $rp_realm = OpenID::Lite::Realm->parse($rp_realm)
            or return $self->ERROR(sprintf q{Invalid realm "%s"}, $rp_realm);
    }
    my $return_to_urls = $self->_discover->discover($rp_realm->build_discovery_url)
        or return $self->ERROR( $self->_discover->errstr );
    return $return_to_urls;
}

sub _build__discover {
    my $self = shift;
    return OpenID::Lite::Provider::Discover->new( agent => $self->agent );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

