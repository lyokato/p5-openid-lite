package OpenID::Lite::RelyingParty::IDResHandler;

use Mouse;

use Params::Validate qw(HASHREF);
use OpenID::Lite::RelyingParty::IDResHandler::Result;
use OpenID::Lite::RelyingParty::IDResHandler::Verifier;
use OpenID::Lite::Constants::ModeType qw(ID_RES SETUP_NEEDED CANCEL);

sub idres {
    my $self = shift;
    my %args = Params::Validate::validate(
        @_,
        {   current_url => 1,
            params      => { type => HASHREF },
            service     => {
                isa      => 'OpenID::Lite::RelyingParty::Discover::Service',
                optional => 1
            },
            association => {
                isa      => 'OpenID::Lite::Association',
                optional => 1
            },
        }
    );

    my $params      = $args{params};
    my $service     = $args{service};
    my $association = $args{association};

    my $mode = $params->get('mode');
    if ( $mode eq ID_RES ) {
        if ( $params->is_openid1 && $params->get('user_setup_url') ) {
            return $self->_create_result_with_status(SETUP_NEEDED);
        }
        my $verifier = $self->_create_verifier(%args)
            or return $self->ERROR();
        my $result = $verifier->verify();
        return $result;
    }
    elsif ( $mode eq SETUP_NEEDED ) {
        unless ( $params->is_openid1 ) {
            return $self->_create_result_with_status(SETUP_NEEDED);
        }
    }
    elsif ( $mode eq CANCEL ) {
        return $self->_create_result_with_status(CANCEL);
    }

    #return $self->ERROR();
    return $self->_create_result_with_status(ERROR);
}

sub _create_verifier {
    my ( $self, %args ) = @_;
    my $verifier;
    if ( $args{params}->is_openid1 ) {
        $verifier
            = OpenID::Lite::RelyingParty::IDResHandler::Verifier::OpenID1
            ->new(%$args);
    }
    elsif ( $args{params}->is_openid2 ) {
        $verifier
            = OpenID::Lite::RelyingParty::IDResHandler::Verifier::OpenID2
            ->new(%$args);
    }
    return $verifier;
}

sub _create_result_with_status {
    my ( $self, $status ) = @_;
    return OpenID::Lite::RelyingParty::IDResHandler::Result->new(
        status => $status, );
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

