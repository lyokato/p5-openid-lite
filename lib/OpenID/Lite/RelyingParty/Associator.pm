package OpenID::Lite::RelyingParty::Associator;

use Any::Moose;
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::Associator';

use OpenID::Lite::SessionHandlers;
use OpenID::Lite::RelyingParty::Associator::Base;
use Carp ();

sub associate {
    my ( $self, $service ) = @_;

    my $associator  = $self->create_method_for( $self->session_type );
    my $association = $associator->associate($service)
        or return $self->ERROR( $associator->errstr );
    return $association;
}

# factory method
sub create_method_for {
    my ( $self, $type ) = @_;
    my $session = OpenID::Lite::SessionHandlers->select_session($type);
    Carp::croak "invalid session type" unless $session;
    my $associator = OpenID::Lite::RelyingParty::Associator::Base->new(
        agent      => $self->agent,
        assoc_type => $self->assoc_type,
        session    => $session,
    );
    return $associator;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

