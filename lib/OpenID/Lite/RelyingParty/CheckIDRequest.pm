package OpenID::Lite::RelyingParty::CheckIDRequest;

use Mouse;
use OpenID::Lite::Params;
use OpenID::Lite::Constants::Namespace qw(SPEC_2_0 IDENTIFIER_SELECT);
use OpenID::Lite::Constants::ModeType qw(CHECKID_SETUP CHECKID_IMMEDIATE);

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
    isa       => 'OpenID::Lite::RelyingParty::Association',
    predicate => 'has_association',
);


has '_params' => (
    is         => 'ro',
    lazy_build => 1,
    handles => {
        _set_param => 'set',
        _get_param => 'get',
    },
);


sub add_extension {
    my ( $self, $extension ) = @_;
}

sub redirect_url {
    my ( $self, %params ) = @_;
    my $params = $self->gen_params(%params);
    my $url = $parmas->to_url( $server->url );
    return $url;
}

sub gen_params {
    my ( $self, %params ) = @_;

    my $mode = $params{immediate}
        ? CHECKID_IMMEDIATE
        : CHECKID_SETUP;
    $self->_set_param( mode => $mode );

    my $realm = $params{realm};
    my $realm_key
        = $service->requires_compatibility_mode
        ? 'trust_root'
        : 'realm';
    $self->_set_param( $realm_key, $realm );

    # check return_to
    # version is 1 ? 
    if ( exists $params{return_to} ) {
        my $return_to = URI->new( $params{return_to} );

        #$return_to->query_form(
        # nonce => gen_nonce(),
        # claimed_id => $claimed_id,
        #);
        $self->_set_param( return_to => $return_to->as_string );
    }

    # identity setting
    my ( $identity, $claimed_id );
    if ( $service->is_op_identifier ) {
        $identity = $claimed_id = IDENTIFIER_SELECT;
    }
    else {
        $identity   = $self->service->op_local_identity;
        $claimed_id = $self->service->claimed_identity;
    }
    $self->_set_param( identity => $identity );
    unless ( $service->requires_compatibility_mode ) {
        $self->_set_param( claimed_id => $claimed_id );
    }

    # association setting
    if ( $self->has_association ) {
        $self->_set_param( assoc_handle => $self->association->handle );
    }


    return $params;
}

sub should_send_redirect {
    my ( $self, %params ) = @_; 
    return 1 $self->service->requires_compatibility_mode;
    my $url = $self->redirect_url( %params );
    return length($url) < 2048;
}

sub _build__parmas {
    my $self = shift;
    my $params = OpenID::Lite::Params->new;
    $params->set( ns => $self->service->preferred_namespace );
    return $params;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME 

=head1 SYNOPSIS

    my $request = OpenID::Lite::RelyingParty::CheckIDRequest->new(
        service     => $service,
        association => $association,
    );

    my $url = $request->redirect_url(
        realm     => $realm,
        return_to => $return_to,
        immediate => 1,
    );

=cut
