package OpenID::Lite::RelyingParty::Associator::ParamExtractor;

use Mouse;
use OpenID::Lite::Association;

has 'session_handler' => (
    is       => 'rw',
    isa      => 'OpenID::Lite::RelyingParty::Associator::SessionHandler',
    required => 1,
);

with 'OpenID::Lite::Role::ErrorHandler';

sub extract_params {
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
