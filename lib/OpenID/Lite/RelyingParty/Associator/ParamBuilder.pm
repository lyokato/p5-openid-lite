package OpenID::Lite::RelyingParty::Associator::ParamBuilder;

use Mouse;
with 'OpenID::Lite::Role::ErrorHandler';

has 'session_handler' => (
    is       => 'rw',
    isa      => 'OpenID::Lite::RelyingParty::Associator::SessionHandler',
    required => 1,
);

use OpenID::Lite::Params;
use OpenID::Lite::Constants::Namespace qw(SPEC_2_0);
use OpenID::Lite::Constants::ModeType qw(ASSOCIATION);

sub build_params {
    my ( $self, $service, $assoc_type ) = @_;
    my $params = OpenID::Lite::Params->new;
    unless ( $service->requires_compatibility_mode ) {
        $params->set( ns => SPEC_2_0 );
    }
    $params->set( mode       => ASSOCIATION );
    $params->set( assoc_type => $assoc_type );
    $self->session_handler->set_request_params($service, $params);
    return $params;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

