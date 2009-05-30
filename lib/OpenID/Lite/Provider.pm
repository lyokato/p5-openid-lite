package OpenID::Lite::Provider;

use Any::Moose;
use OpenID::Lite::Message;
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

sub rp_discover {
    my ( $self, $rp_realm ) = @_;
    my $return_to_urls = $self->_discover->discover($rp_realm)
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

