package OpenID::Lite::RelyingParty::Associator::ParamExtractor;

use Mouse;
use OpenID::Lite::Association;
use OpenID::Lite::RelyingParty::Associator::SessionHandler::NoEncryption;
use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION);

has 'session_handler' => (
    is       => 'rw',
    isa      => 'OpenID::Lite::RelyingParty::Associator::SessionHandler',
    required => 1,
);

with 'OpenID::Lite::Role::ErrorHandler';

sub extract_params {
    my ( $self, $params ) = @_;

    my $assoc_handle = $params->get('assoc_handle')
        or return $self->ERROR(q{Missing parameter, "assoc_handle".});

    my $expires_in = $params->get('expires_in')
        or return $self->ERROR(q{Missing parameter, "expires_in".});
    unless ( $expires_in =~ /^\d+$/ ) {
        return $self->ERROR( sprintf q{Invalid expires_in, "%s"},
            $expires_in );
    }

    my $session_type = $params->get('session_type');
    unless ($session_type) {
        unless ( $params->is_openid2 ) {
            $session_type = NO_ENCRYPTION;
        }
        else {
            return $self->ERROR(q{Missing parameter, "session_type"});
        }
    }

    unless ( $self->session_handler->match($session_type) ) {

        # found session mismatch

        if ( $params->is_openid1 && $session_type eq NO_ENCRYPTION ) {

            my $no_encryption_handler
                = OpenID::Lite::RelyingParty::Associator::SessionHandler::NoEncryption
                ->new;
            $self->session_handler($no_encryption_handler);

        }
        else {
            return $self->ERROR(
                sprintf
                    q{Session Type Mismatch: server response includes session type "%s"},
                $session_type
            );
        }
    }

    my $assoc_type = $params->get('assoc_type')
        or return $self->ERROR(q{Missing paramter, "assoc_type".});
    unless ( $self->session_handler->can_handle_assoc_type($assoc_type) ) {
        # protocol error
        return $self->ERROR(
            sprintf q{Server responds with unsupported assoc_type, "%s" },
            $assoc_type );
    }

    my $secret = $self->session_handler->extract_secret($params)
        or return $self->ERROR( $self->session_handler->errstr );

    my $association = OpenID::Lite::Association->new(
        type       => $assoc_type,
        handle     => $assoc_handle,
        expires_in => $expires_in,
        secret     => $secret,
        issued     => time(),
    );
    return $association;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;
