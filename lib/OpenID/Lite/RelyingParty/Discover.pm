package OpenID::Lite::RelyingParty::Discover;

use Any::Moose;
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::Discoverer';
with 'OpenID::Lite::Role::AgentHandler';

use OpenID::Lite::RelyingParty::Discover::Method::XRI;
use OpenID::Lite::RelyingParty::Discover::Method::URL;

sub discover {
    my ( $self, $identity ) = @_;
    my $disco = $self->create_method_for( $identity );
    return $disco->discover( $identity )
        || $self->ERROR( $disco->errstr );
}

# factory method
sub create_method_for {
    my ( $self, $identity ) = @_;
    my $disco
        = $identity->is_xri
        ? OpenID::Lite::RelyingParty::Discover::Method::XRI->new(
        agent => $self->agent )
        : OpenID::Lite::RelyingParty::Discover::Method::URL->new(
        agent => $self->agent );
    return $disco;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

