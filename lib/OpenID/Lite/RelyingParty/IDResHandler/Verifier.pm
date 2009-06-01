package OpenID::Lite::RelyingParty::IDResHandler::Verifier;
use Any::Moose;

use URI;
use List::MoreUtils qw(any);
use Any::MooseX::Types::URI qw(Uri);
use OpenID::Lite::Nonce;

has 'params' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::Message',
    required => 1,
);

has 'current_url' => (
    is        => 'ro',
    isa       => Uri,
    coerce    => 1,
    predicate => 'has_current_url',
);

has 'service' => (
    is        => 'ro',
    isa       => 'OpenID::Lite::RelyingParty::Discover::Service',
    predicate => 'has_service',
);

has 'association' => (
    is        => 'ro',
    isa       => 'OpenID::Lite::Association',
    predicate => 'has_association',
);

with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::ErrorHandler';

my @OP1_FIELDS     = qw(return_to assoc_handle sig signed identity);
my @OP1_SIG_FIELDS = qw(return_to identity);

my @OP2_FIELDS = qw(return_to assoc_handle sig signed op_endpoint);
my @OP2_SIG_FIELDS
    = qw(return_to identity response_nonce claimed_id assoc_handle);

sub verify {
    my $self = @_;
    $self->_check_for_fields()              or return;
    $self->_verify_return_to()              or return;
    $self->_verify_discovered_information() or return;
    $self->_check_nonce()                   or return;
    $self->_verify_signature()              or return;
    return 1;
}

sub _check_for_fields {
    my $self = shift;

    my ( @fields, @signed_fields );
    if ( $self->params->is_openid1 ) {
        @fields        = @OP1_FIELDS;
        @signed_fields = @OP1_SIG_FIELDS;
    }
    else {
        @fields        = @OP2_FIELDS;
        @signed_fields = @OP2_SIG_FIELDS;
    }

    my $signed = $self->params->get('signed')
        or $self->ERROR(q{signed key not found.});
    my @signed = split /,/, $signed;

    for my $field (@fields) {
        unless ( $self->param->has_key($field) ) {
            return $self->ERROR( sprintf q{"%s" key not found}, $field );
        }
    }
    for my $field (@signed_fields) {
        unless ( $self->param->has_key($field)
            && ( any { $field eq $_ } @signed ) )
        {
            return $self->ERROR( sprintf q{"%s" key not found}, $field );
        }
    }
}

sub _verify_return_to {
    my $self = shift;

    my $url = $self->params->get('return_to');
    unless ( $url && $url =~ /^https?\:\/\// ) {
        return;
    }
    my $return_to = URI->new($url)->canonical;
    $self->_verify_return_to_args($return_to)
        or return;
    if ( $self->has_current_url ) {
        $self->_verify_return_to_base($return_to)
            or return;
    }
    return 1;
}

sub _verify_return_to_args {
    my ( $self, $return_to ) = @_;
}

sub _verify_return_to_base {
    my ( $self, $return_to ) = @_;
    my $current_url = $self->current_url;
    for my $meth (qw(scheme host port path)) {
        return $self->ERROR(
            sprintf q{"%s" in response parameter wasn't match to "%s"},
            $return_to->as_string, $current_url->as_string )
            unless $current_url->$meth eq $return_to->$meth;
    }
    return 1;
}

sub _verify_discovered_infomation {
    my $self = shift;
    if ( $self->params->is_openid1 ) {

    }
    elsif ( $self->params->is_openid2 ) {

        # claimed_id && identity both or none?
        my $claimed_id = $self->params->get('claimed_id');
        my $identity   = $self->params->get('identity');

        if ( $claimed_id && !$identity ) {
            return $self->ERROR();
        }
        elsif ( !$claimed_id && $identity ) {
            return $self->ERROR();
        }
        elsif ( !$claimed_id ) {

            # if no claimed_id
            my $service = OpenID::Lite::RelyingParty::Discover::Service->new;
            $service->add_url( $self->params->get('op_endpoint') );
            $self->service($service);
            return;
        }

        if ( $self->has_service ) {

        }
        else {

        }
    }
    else {

        # error
    }
}

sub _check_nonce {
    my $self = shift;
    my ( $nonce, $server_url );
    if ( $self->params->is_openid1 ) {
        $nonce      = $self->params->get_extra('rp_nonce'); # TODO: get extra params
        $server_url = '';
    }
    elsif ( $self->params->is_openid2 ) {
        $nonce = $self->params->get('response_nonce');
        $server_url = $self->has_server ? $self->server->url : undef;
    }
    else {
        return $self->ERROR(q{IdRes Response doesn't have proper ns value.});
    }

    unless ($nonce) {
        return $self->ERROR(q{No proper nonce found.});
    }

    my ( $timestamp, $unique ) = OpenID::Lite::Nonce->split_nonce($nonce)
        or
        return $self->ERROR( sprintf q{Invalid response_nonce format. "%s"},
        $nonce );

    # XXX:check obtained timestamp and unique included in nonce

    return 1;
}

sub _verify_signature {
    my $self = @_;
    my $sig_verifier = $self->create_signature_verifier();
    $sig_verifier->verify( $self->params )
        or return $self->ERROR( $sig_verifier->errstr );
}

sub create_signature_verifier {
    my ( $self, $assertion ) = @_;
    my $sig_verifier
        = (    $self->has_association
            && !$self->params->get('invalidate_handle')
            && !$self->association->is_expired )
        ? OpenID::Lite::RelyingParty::IDResHandler::SignatureVerifier::Association->new()
        : OpenID::Lite::RelyingParty::IDResHandler::SignatureVerifier::DirectCommunication->new();
    return $sig_verifier;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

