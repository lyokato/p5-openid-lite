package OpenID::Lite::Provider;

use Any::Moose;
use OpenID::Lite::Params;
use OpenID::Lite::Provider::Handler::Factory;

has '_handler_factory' => (
    is      => 'ro',
    isa     => 'OpenID::Lite::Provider::Handler::Factory',
    default => sub { OpenID::Lite::Provider::Handler::Factory->new },
);

with 'OpenID::Lite::Role::ErrorHandler';

sub handle_request {
    my ( $self, $request ) = @_;
    my $req_params = $self->_build_request_params($request);
    my $handler = $self->_handler_factory->create_handler_for($req_params)
        or return $self->ERROR(q{Proper handler not found.});
    my $res = $handler->handle_request($req_params);
    return $res;
}

sub _build_request_params {
    my ( $self, $request ) = @_;
    my $params = OpenID::Lite::Params->from_request($request);
    return $params;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
