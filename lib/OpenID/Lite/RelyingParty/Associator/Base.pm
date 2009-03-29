package OpenID::Lite::RelyingParty::Associator::Base;

use Any::Moose;
with 'OpenID::Lite::Role::Associator';
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::ErrorHandler';

use OpenID::Lite::RelyingParty::Associator::ParamBuilder;
use OpenID::Lite::RelyingParty::Associator::ParamExtractor;
use OpenID::Lite::RelyingParty::DirectCommunication;

has 'session' => (
    is       => 'rw',
    isa      => 'OpenID::Lite::SessionHandler',
    required => 1,
);

has '_direct_communication' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_param_builder' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_param_extractor' => (
    is         => 'ro',
    lazy_build => 1,
);

sub associate {
    my ( $self, $service ) = @_;
    my $req_params
        = $self->_param_builder->build_params( $service, $self->assoc_type );
    my $res_params
        = $self->_direct_communication->send_request( $service->url,
        $req_params )
        or return $self->ERROR( $self->_direct_communication->errstr );
    my $association = $self->_param_extractor->extract_params($res_params)
        or return $self->ERROR( $self->_param_extractor->errstr );
    return $association;
}

sub _build__param_builder {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Associator::ParamBuilder->new(
        session => $self->session, );
}

sub _build__param_extractor {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Associator::ParamExtractor->new(
        session => $self->session, );
}

sub _build__direct_communication {
    my $self = shift;
    return OpenID::Lite::RelyingParty::DirectCommunication->new(
        agent => $self->agent, );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

