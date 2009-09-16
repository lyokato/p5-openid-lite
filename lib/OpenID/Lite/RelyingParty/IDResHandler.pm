package OpenID::Lite::RelyingParty::IDResHandler;

use Any::Moose;
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';

use Params::Validate;
use OpenID::Lite::RelyingParty::CheckID::Result;
use OpenID::Lite::RelyingParty::IDResHandler::Verifier;
use OpenID::Lite::Constants::ModeType qw(ID_RES SETUP_NEEDED CANCEL ERROR_MODE);
use OpenID::Lite::Constants::CheckIDResponse qw(:all);

has 'store' => (
    is   => 'ro',
    does => 'OpenID::Lite::Role::Storable',
);

sub idres {
    my $self = shift;
    my %args = Params::Validate::validate(
        @_,
        {   current_url => 1,
            params      => {
                isa => 'OpenID::Lite::Message',
            },
            service     => {
                isa      => 'OpenID::Lite::RelyingParty::Discover::Service',
                optional => 1
            },
        }
    );

    my $params  = $args{params};
    my $service = $args{service};

    my $mode = $params->get('mode');
    if ( !$mode ) {
        return OpenID::Lite::RelyingParty::CheckID::Result->new(
            type    => IS_NOT_OPENID,
            params  => $params,
            message => sprintf(q{Unknown mode, "%s"}, $mode),
        );
    }
    elsif ( $mode eq ID_RES ) {
        if ( $params->is_openid1 && $params->get('user_setup_url') ) {
            return OpenID::Lite::RelyingParty::CheckID::Result->new(
                type   => IS_SETUP_NEEDED,
                params => $params,
                url    => $params->get('user_setup_url'),
            );
        }
        $args{agent} = $self->agent;
        $args{store} = $self->store if $self->store;
        my $verifier = OpenID::Lite::RelyingParty::IDResHandler::Verifier->new(%args);
        if ( $verifier->verify() ) {
            return OpenID::Lite::RelyingParty::CheckID::Result->new(
                type    => IS_SUCCESS,
                params  => $params,
                service => $verifier->service,
            );
        } else {
            return OpenID::Lite::RelyingParty::CheckID::Result->new(
                type    => IS_INVALID,
                params  => $params,
                message => $verifier->errstr,
            );
        };
    }
    elsif ( $mode eq SETUP_NEEDED ) {
        unless ( $params->is_openid1 ) {
            return OpenID::Lite::RelyingParty::CheckID::Result->new(
                type   => IS_SETUP_NEEDED,
                params => $params,
                url    => $params->get('user_setup_url') || '',
            );
        }
    }
    elsif ( $mode eq CANCEL ) {
        return OpenID::Lite::RelyingParty::CheckID::Result->new(
            type   => IS_CANCELED,
            params => $params,
        );
    }
    elsif ( $mode eq ERROR_MODE ) {
        my $error     = $params->get('error')     || '';
        my $contact   = $params->get('contact')   || '';
        my $reference = $params->get('reference') || '';
        return OpenID::Lite::RelyingParty::CheckID::Result->new(
            type      => IS_ERROR,
            message   => $error,
            contact   => $contact,
            reference => $reference,
            params    => $params,
        );
    }
    return OpenID::Lite::RelyingParty::CheckID::Result->new(
        type    => IS_INVALID,
        params  => $params,
        message => sprintf(q{Unknown mode, "%s"}, $mode),
    );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

