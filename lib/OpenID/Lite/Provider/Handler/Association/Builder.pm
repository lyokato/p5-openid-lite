package OpenID::Lite::Provider::Handler::Association::Builder;

use Any::Moose;
use OpenID::Lite::Constants::SessionType qw(:all);
use OpenID::Lite::SessionHandlers;
use OpenID::Lite::Provider::Handler::Association;
with 'OpenID::Lite::Role::ErrorHandler';

sub build_from_params {
    my ( $self, $params ) = @_;
    my $session_type;
    my $req_session_type = $params->get('session_type');
    if ( $params->is_openid1 ) {
        $session_type
            = $req_session_type
            ? $req_session_type
            : NO_ENCRYPTION;
    }
    elsif ( $params->is_openid2 ) {
        return $self->ERROR(q{Missing parameter, "session_type".})
            unless $req_session_type;
    }
    else {
        return $self->ERROR(q{Missing or invalid parameter, "ns"});
    }
    my $session = OpenID::Lite::SessionHandlers->select_session($session_type)
        or return $self->ERROR( sprintf q{Invalid session type, "%s"},
        $session_type || '' );
    my $assoc_type = $params->get('assoc_type') || '';
    unless ( $session->can_handle_assoc_type($assoc_type) ) {
        return $self->ERROR(
            sprintf q{Session type "%s" can't work with assoc_type "%s"},
            $session_type, $assoc_type );
    }
    my $handler = OpenID::Lite::Provider::Handler::Association->new(
        session    => $session,
        assoc_type => $assoc_type,
    );
    return $handler;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

