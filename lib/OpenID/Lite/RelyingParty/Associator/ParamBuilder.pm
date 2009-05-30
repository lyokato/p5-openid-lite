package OpenID::Lite::RelyingParty::Associator::ParamBuilder;

use Any::Moose;
with 'OpenID::Lite::Role::ErrorHandler';

has 'session' => (
    is       => 'rw',
    isa      => 'OpenID::Lite::SessionHandler',
    required => 1,
);

use OpenID::Lite::Message;
use OpenID::Lite::Constants::Namespace qw(SPEC_2_0);
use OpenID::Lite::Constants::ModeType qw(ASSOCIATION);

sub build_params {
    my ( $self, $service, $assoc_type ) = @_;
    my $params = OpenID::Lite::Message->new;
    unless ( $service->requires_compatibility_mode ) {
        $params->set( ns => SPEC_2_0 );
    }
    $params->set( mode       => ASSOCIATION );
    $params->set( assoc_type => $assoc_type );
    $self->session->set_request_params( $service, $params );
    return $params;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

