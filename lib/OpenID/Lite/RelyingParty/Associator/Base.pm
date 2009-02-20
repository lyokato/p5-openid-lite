package OpenID::Lite::RelyingParty::Associator::Base;

use Mouse;
extends 'OpenID::Lite::RelyingParty::DirectCommunication';
with 'OpenID::Lite::Role::Associator';

use OpenID::Lite::Association;
use OpenID::Lite::Constants::Namespace qw(SPEC_2_0);
use OpenID::Lite::Constants::ModeType qw(ASSOCIATION);

has 'session_handler' => (
    is       => 'rw',
    isa      => 'OpenID::Lite::RelyingParty::Associator::SessionHandler',
    required => 1,
);

sub associate {
    my ( $self, $service ) = @_;
    my $req_params = $self->_build_params($service);
    my $res_params = $self->send_request( $service->url, $req_params )
        or return;
    my $association = $self->_extract_response($res_params)
        or return;
    return $association;
}

sub _build_params {
    my ( $self, $service ) = @_;
    my $params = OpenID::Lite::Params->new;
    unless ( $service->requires_compatibility_mode ) {
        $params->set( ns => SPEC_2_0 );
    }
    $params->set( mode       => ASSOCIATION );
    $params->set( assoc_type => $self->assoc_type );
    if (  !$service->requires_compatibility_mode
        || $self->session_type ne NO_ENCRYPTION )
    {
        $params->set( session_type => $self->session_type );
    }
    $self->session_handler->set_request_params($params);
}

sub _extract_response {
    my ( $self, $params ) = @_;

    my $assoc_type   = $params->get('assoc_type');
    my $assoc_handle = $params->get('assoc_handle');
    my $session_type = $params->get('session_type');
    my $expires_in   = $params->get('expires_in');

    # check expiry

    unless ( $self->session_handler->match($session_type) ) {

        # openid1 && no-encryption -> handle as no-encryption
        # another pattern -> protocol error
    }

    unless ( $self->session_handler->can_handle_assoc_type($assoc_type) ) {

        # protocol error
    }

    my $secret      = $self->session_handler->extract_secret($params);
    my $association = OpenID::Lite::Association->new(
        type       => $assoc_type,
        handle     => $assoc_handle,
        expires_in => $expires_in,
        secret     => $secret,
    );
    return $association;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

