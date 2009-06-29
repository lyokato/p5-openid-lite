package OpenID::Lite::Provider::Response;

use Any::Moose;
use OpenID::Lite::Constants::ProviderResponseType qw(:all);
use OpenID::Lite::Constants::ModeType qw(:all);
use OpenID::Lite::Constants::Namespace qw(:all);
use OpenID::Lite::Message;
use OpenID::Lite::Realm;
use OpenID::Lite::Nonce;
use OpenID::Lite::SignatureMethods;
use URI;

has 'type' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'setup_url' => (
    is      => 'ro',
    isa     => 'Str',
    default => '',
);

has 'endpoint_url' => (
    is      => 'ro',
    isa     => 'Str',
    default => '',
);

has 'setup_params' => (
    is  => 'ro',
    isa => 'HashRef',
);

has 'assoc_builder' => (
    is => 'ro',
);

has 'req_params' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::Message',
    required => 1,
);

has 'res_params' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::Message',
    required => 1,
);

has 'errstr' => (
    is      => 'ro',
    isa     => 'Str',
    default => '',
);

sub is_for_setup {
    my $self = shift;
    return $self->type eq SETUP;
}

sub is_for_direct_communication {
    my $self = shift;
    return $self->type eq DIRECT;
}

sub is_checkid_error {
    my $self = shift;
    return $self->type eq CHECKID_ERROR;
}

sub is_positive_assertion {
    my $self = shift;
    return $self->type eq POSITIVE_ASSERTION;
}

sub requires_setup {
    my $self = shift;
    return $self->type eq REQUIRES_SETUP;
}

sub add_extension {
    my ( $self, $extension ) = @_;
    confess
        q{add_extension works when is_for_setup or is_positive_assertion returns true}
        unless $self->is_for_setup || $self->is_positive_assertion;
    $extension->append_to_params( $self->res_params );
}

sub make_signed_url {
    my $self = shift;
    confess
        q{make_singed_url works when is_for_setup or is_positive_assertion returns true}
        unless $self->is_for_setup || $self->is_positive_assertion;

    my $identity     = $self->res_params->get('identity');
    my $claimed_id   = $self->res_params->get('claimed_id');
    my $return_to    = $self->res_params->get('return_to');
    my $assoc_handle = $self->res_params->get('assoc_handle');
    my $ns           = $self->res_params->get('ns');
    my $realm        = $self->res_params->get('realm')
                    || $self->res_params->get('trust_root');

    unless ( OpenID::Lite::Realm->check_url( $realm, $return_to ) ) {
        $self->errstr(q{Invalid realm});
        return;
    }

    # check association
    my $assoc;
    my $invalidate_handle;
    if ($assoc_handle) {
        my $found = $self->assoc_builder->build_from_handle(
            $assoc_handle => { dumb => 0, } );
        if ( $found && !$found->is_expired ) {
            $assoc = $found;
        }
        else {
            $invalidate_handle = $assoc_handle;
        }
    }

    unless ($assoc) {

        $assoc = $self->assoc_builder->build_association(
            type => q{HMAC-SHA1},
            dumb => 1,
        );
    }

    $claimed_id ||= $identity;
    $claimed_id = $identity if $claimed_id eq IDENTIFIER_SELECT;

    #my $res_params = OpenID::Lite::Message->new;
    my $res_params = $self->res_params->copy();
    $res_params->set( ns => $ns ) if $ns;

    $res_params->set( mode         => ID_RES );
    $res_params->set( identity     => $identity );
    $res_params->set( return_to    => $return_to );
    $res_params->set( assoc_handle => $assoc->handle );

    $res_params->set( invalidate_handle => $invalidate_handle )
        if $invalidate_handle;

    if ( $res_params->is_openid2 ) {
        $res_params->set( claimed_id     => $claimed_id );
        $res_params->set( response_nonce => OpenID::Lite::Nonce->gen_nonce );
        $res_params->set( op_endpoint    => $self->endpoint_url );
    }

    $res_params->set_signed();
    my $signature_method
        = OpenID::Lite::SignatureMethods->select_method( $assoc->type );
    my $signature = $signature_method->sign( $assoc->secret, $res_params );
    $res_params->set( sig => $signature );
    return $res_params->to_url($return_to);
}

sub make_cancel_url {
    my $self   = shift;
    my $params = OpenID::Lite::Message->new;
    $params->set( ns => $self->req_params->get('ns') )
        if $self->req_params->get('ns');
    $params->set( mode => CANCEL );
    return $params->to_url( $self->req_params->get('return_to') );
}

sub make_setup_url {
    my $self = shift;
    confess q{no setup_url found.} unless $self->setup_url;
    confess
        q{make_setup_url works when requires_setup or is_for_setup returns true.}
        unless $self->requires_setup || $self->is_for_setup;

    my $params = OpenID::Lite::Message->new;
    my $surl   = URI->new( $self->setup_url );
    $surl->query_form( %{ $self->setup_params } )
        if $self->setup_params;

    my $mode = $self->req_params->get('mode');
    if ( $mode eq CHECKID_IMMEDIATE ) {
        if ( $self->req_params->is_openid2 ) {
            $params->set( ns   => $self->req_params->get('ns') );
            $params->set( mode => SETUP_NEEDED );
        }
        else {
            $params->set( mode           => ID_RES );
            $params->set( user_setup_url => $surl->as_string );
        }
    }
    return $params->to_url( $self->req_params->get('return_to') );
}

sub make_error_url {
    my $self = shift;
    unless ( $self->is_checkid_error ) {
        confess 'make_error_url can be called only when the response-type is checkid error.';
    }
    $self->res_params->to_url( $self->req_params->get('return_to') );
}

sub content {
    my $self = shift;
    if ( $self->is_for_direct_communication ) {
        return $self->res_params->to_key_value;
    }
    else {
        confess
            q{content shouldn't be called when the response is for redirect or setup};
    }
}

sub get_realm {
    my $self = shift;
    confess
        q{get_realm works when is_for_setup or is_positive_assertion returns true}
        unless $self->is_for_setup || $self->is_positive_assertion;
    return $self->res_params->get('realm') || $self->res_params->get('trust_root');
}

sub get_identity {
    my $self = shift;
    confess
        q{get_identity works when is_for_setup or is_positive_assertion returns true}
        unless $self->is_for_setup || $self->is_positive_assertion;
    return $self->res_params->get('identity');
}

sub set_identity {
    my $self = shift;
    my $identity = shift;
    confess
        q{get_identity works when is_for_setup or is_positive_assertion returns true}
        unless $self->is_for_setup || $self->is_positive_assertion;
    return $self->res_params->set('identity' => $identity);
}

sub get_claimed_id {
    my $self = shift;
    confess
        q{get_claimed_id works when is_for_setup or is_positive_assertion returns true}
        unless $self->is_for_setup || $self->is_positive_assertion;
    return $self->res_params->get('claimed_id');
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
