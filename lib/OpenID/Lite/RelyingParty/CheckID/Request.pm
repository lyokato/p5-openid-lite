package OpenID::Lite::RelyingParty::CheckID::Request;

use Any::Moose;
use URI;
use OpenID::Lite::Message;
use OpenID::Lite::Constants::Namespace qw(SPEC_2_0 IDENTIFIER_SELECT);
use OpenID::Lite::Constants::ModeType qw(CHECKID_SETUP CHECKID_IMMEDIATE);
use OpenID::Lite::Nonce;

has 'anonymous' => (
    is      => 'rw',
    isa     => 'Bool',
    default => 0,
);

has 'service' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::RelyingParty::Discover::Service',
    required => 1,
);

has 'association' => (
    is        => 'ro',
    isa       => 'OpenID::Lite::Association',
    predicate => 'has_association',
);

has '_params' => (
    is         => 'ro',
    lazy_build => 1,
    handles    => {
        _set_param => 'set',
        _get_param => 'get',
    },
);

sub add_extension {
    my ( $self, $extension ) = @_;
    # XXX: check service endpoint includes proper Type element for indicated
    #      extension.
    # if ( $self->service->can_handle_extension($extension) ) {
    $extension->append_to_params($self->_params);
    # }
}

sub redirect_url {
    my ( $self, %args ) = @_;
    $self->gen_params(%args);
    my $url = $self->_params->to_url( $self->service->url );
    return $url;
}

sub gen_params {
    my ( $self, %args ) = @_;

    my $mode
        = $args{immediate}
        ? CHECKID_IMMEDIATE
        : CHECKID_SETUP;
    $self->_set_param( mode => $mode );

    my $realm = $args{realm};
    my $realm_key
        = $self->service->requires_compatibility_mode
        ? 'trust_root'
        : 'realm';
    $self->_set_param( $realm_key, $realm );

    if ( exists $args{return_to} ) {
        my $return_to = URI->new( $args{return_to} );
        if ( $self->service->requires_compatibility_mode ) {
            $return_to->query_form(
                rp_nonce           => OpenID::Lite::Nonce->gen_nonce(),
                openid1_claimed_id => $self->service->claimed_identifier,
            );
        }
        $self->_set_param( return_to => $return_to->as_string );
    }

    # identity setting
    unless ( $self->anonymous ) {
        my ( $identity, $claimed_id );
        if ( $self->service->is_op_identifier ) {
            $identity = $claimed_id = IDENTIFIER_SELECT;
        }
        else {
            $identity   = $self->service->find_local_identifier;
            $claimed_id = $self->service->claimed_identifier;
        }
        $self->_set_param( identity => $identity );
        unless ( $self->service->requires_compatibility_mode ) {
            $self->_set_param( claimed_id => $claimed_id );
        }
    }

    # association setting
    if ( $self->has_association ) {
        $self->_set_param( assoc_handle => $self->association->handle );
    }

}

sub should_send_redirect {
    my ( $self, %args ) = @_;
    return 1 if $self->service->requires_compatibility_mode;
    my $url = $self->redirect_url(%args);
    return length($url) < 2048;
}

sub _build__params {
    my $self   = shift;
    my $params = OpenID::Lite::Message->new;
    $params->set( ns => $self->service->preferred_namespace );
    return $params;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
