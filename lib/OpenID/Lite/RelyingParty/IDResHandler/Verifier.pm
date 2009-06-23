package OpenID::Lite::RelyingParty::IDResHandler::Verifier;
use Any::Moose;

use URI;
use List::MoreUtils qw(any);
use OpenID::Lite::Nonce;
use OpenID::Lite::Util::URI;
use OpenID::Lite::Util::XRI;
use OpenID::Lite::SignatureMethods;
use OpenID::Lite::Identifier;
use OpenID::Lite::RelyingParty::DirectCommunication;
use OpenID::Lite::RelyingParty::Discover;
use OpenID::Lite::RelyingParty::Discover::Service;
use OpenID::Lite::Constants::Namespace
    qw(SPEC_1_0 SPEC_2_0 SIGNON_1_1 SIGNON_1_0 SIGNON_2_0 SERVER_2_0);
use OpenID::Lite::Constants::ModeType qw(CHECK_AUTHENTICATION);

has 'params' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::Message',
    required => 1,
);

has 'current_url' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'service' => (
    is        => 'rw',
    isa       => 'OpenID::Lite::RelyingParty::Discover::Service',
    predicate => 'has_service',
);

has 'store' => (
    is => 'ro',

    #does => 'OpenID::Lite::Role::Storable',
);

has '_discoverer' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_direct_communication' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::RelyingParty::DirectCommunication',
    lazy_build => 1,
);

with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::ErrorHandler';

my @OP1_FIELDS     = qw(return_to assoc_handle sig signed identity);
my @OP1_SIG_FIELDS = qw(return_to identity);

my @OP2_FIELDS     = qw(return_to assoc_handle sig signed op_endpoint);
my @OP2_SIG_FIELDS = qw(return_to response_nonce assoc_handle);

sub verify {
    my $self = shift;
    $self->_check_for_fields() or return;
    $self->_verify_return_to() or return;

    $self->_verify_discovery_results() or return;
    $self->_check_nonce()     or return;
    $self->_check_signature() or return;

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
        unless ( $self->params->has_key($field) ) {
            return $self->ERROR( sprintf q{"%s" key not found}, $field );
        }
    }
    for my $field (@signed_fields) {
        unless ( $self->params->has_key($field)
            && ( any { $field eq $_ } @signed ) )
        {
            return $self->ERROR( sprintf q{"%s" key not found}, $field );
        }
    }
    return 1;
}

sub _verify_return_to {
    my $self = shift;

    my $url = $self->params->get('return_to');
    return unless $url;
    $url = OpenID::Lite::Util::URI->normalize($url);
    return unless $url;
    return unless OpenID::Lite::Util::URI->is_uri($url);

    $self->_verify_return_to_args($url)
        or return;
    $self->_verify_return_to_base($url)
        or return;
    return 1;
}

sub _verify_return_to_args {
    my ( $self, $return_to ) = @_;
    $return_to = URI->new($return_to);
    my %parsed = $return_to->query_form();

    for my $key ( keys %parsed ) {
        my $msg_val = $self->params->get_extra($key);
        return $self->ERROR(
            sprintf q{Message missing return_to argument, "%s"}, $key )
            unless $msg_val;
        return $self->ERROR(
            sprintf
                q{Parameter [%s]s value [%s] doesn't match return_to's value [%s]},
            $key, $msg_val, $parsed{$key} )
            if ( $msg_val ne $parsed{$key} );
    }

    for my $key ( @{ $self->params->get_extra_keys() } ) {
        my $msg_val = $self->params->get_extra($key);
        return $self->ERROR(
            q{Unexpected parameter (not on return_to), [%s = %s]},
            $key, $msg_val )
            if not exists $parsed{$key};
        if ( $msg_val eq $parsed{$key} ) {
            return $self->ERROR(
                sprintf
                    q{Parameter [%s]s value [%s] doesn't match return_to's value [%s]},
                $key, $msg_val, $parsed{$key} );
        }
    }

    return 1;
}

sub _verify_return_to_base {
    my ( $self, $return_to ) = @_;
    $return_to = URI->new($return_to);
    my $current_url = URI->new( $self->current_url );
    for my $meth (qw(scheme host port path)) {
        return $self->ERROR(
            sprintf q{"%s" in response parameter wasn't match to "%s"},
            $return_to->as_string, $current_url->as_string )
            unless $current_url->$meth eq $return_to->$meth;
    }
    return 1;
}

sub _verify_discovery_single {
    my ( $self, $endpoint, $to_match ) = @_;
    for my $type_uri ( @{ $to_match->types } ) {
        return $self->ERROR(q{Type uri mismatch.})
            unless $endpoint->has_type($type_uri);
    }

    my $defragged_claimed_id;
    my $scheme = OpenID::Lite::Util::XRI->identifier_scheme(
        $to_match->claimed_identifier );
    if ( $scheme eq 'xri' ) {
        $defragged_claimed_id = $to_match->claimed_identifier;
    }
    elsif ( $scheme eq 'uri' ) {
        if (OpenID::Lite::Util::URI->is_uri( $to_match->claimed_identifier ) )
        {
            my $parsed = URI->new( $to_match->claimed_identifier );
            $parsed->fragment(undef);
            $defragged_claimed_id = $parsed->as_string;
        }
        else {
            $defragged_claimed_id = $to_match->claimed_identifier;
        }
    }
    else {
        return $self->ERROR(
            sprintf q{Invalid claimed_id, "%s"},
            $to_match->claimed_identifier || ''
        );
    }

    if ( $defragged_claimed_id ne $endpoint->claimed_identifier ) {
        return $self->ERROR(
            sprintf q{Claimed IDs don't match, "%s" and "%s" },
            $defragged_claimed_id, $endpoint->claimed_identifier );
    }

    if ($endpoint->find_local_identifier ne $to_match->find_local_identifier )
    {
        return $self->ERROR(
            sprintf q{Local IDs don't match, "%s" and "%s" },
            $to_match->find_local_identifier,
            $endpoint->find_local_identifier
        );
    }

    if ( !$to_match->url ) {
        if ( $to_match->preferred_namespace ne SPEC_1_0 ) {
            return $self->ERROR(
                q{ensure that endpoint is openid2.0 without openid.op_endpoint?}
            );
        }
    }
    elsif ( $endpoint->url ne $to_match->url ) {
        return $self->ERROR( sprintf q{OP endpoint mismatch, "%s" and "%s"},
            $endpoint->url, $to_match->url );
    }
    return 1;
}

sub _verify_discovered_services {
    my ( $self, $claimed_id, $services, $to_match_endpoints ) = @_;

    my @failure_messages;
    for my $service ( @$services ) {
        for my $to_match ( @$to_match_endpoints ) {
            if ( $self->_verify_discovery_single($service, $to_match) ) {
                $self->service($service);
                return 1;
            } else {
                push(@failure_messages, $self->errstr);
                $self->ERROR(undef);
            }
        }
    }
    return $self->ERROR(
        sprintf q{No matching endpoint found for claimed_id "%s".}, $claimed_id);
}

sub _discover_and_verify {
    my ( $self, $claimed_id, $to_match_endpoints ) = @_;
    $claimed_id = OpenID::Lite::Identifier->normalize($claimed_id);
    my $services = $self->_discoverer->discover($claimed_id)
        or return $self->ERROR( $self->_discoverer->errstr );
    unless ( @$services > 0 ) {
        return $self->ERROR( sprintf q{No OpenID information found at %s},
            $claimed_id );
    }
    use Data::Dump qw(dump);
    return $self->_verify_discovered_services( $claimed_id, $services,
        $to_match_endpoints );
}

sub _verify_discovery_results_openid1 {
    my $self       = shift;

    my $claimed_id = $self->params->get_extra('openid1_claimed_id');

    unless ($claimed_id) {
        if ( $self->has_service && $self->service->claimed_identifier ) {
            $claimed_id = $self->service->claimed_identifier;
        }
        else {
            return $self->ERROR(q{When using OpenID 1, the claimed id must be supplied,
                either by passing it through as a return_to parameter or by using a
                session, and supplied to the IDResHandler when it is constructed.});
        }
    }

    my $to_match = OpenID::Lite::RelyingParty::Discover::Service->new;
    $to_match->op_local_identifier( $self->params->get('identity') );
    $to_match->claimed_identifier($claimed_id);

    my $to_match_1_0 = $to_match->copy();
    $to_match->add_type(SIGNON_1_1);
    $to_match_1_0->add_type(SIGNON_1_0);

    if ( $self->has_service ) {
        my $verified = $self->_verify_discovery_single( $self->service, $to_match )
                    || $self->_verify_discovery_single( $self->service, $to_match_1_0 );
        return 1 if $verified;
    }

    return $self->_discover_and_verify(
        $to_match->claimed_identifier,
        [$to_match, $to_match_1_0]
    );
}

sub _verify_discovery_results_openid2 {
    my $self = shift;
    my $to_match = OpenID::Lite::RelyingParty::Discover::Service->new;
    $to_match->add_type(SIGNON_2_0);
    $to_match->add_uri( $self->params->get('op_endpoint') );

    # claimed_id && identity both or none?
    my $claimed_id = $self->params->get('claimed_id');
    my $identity   = $self->params->get('identity');

    $to_match->claimed_identifier($claimed_id);
    $to_match->op_local_identifier($identity);

    if ( $claimed_id && !$identity ) {
        return $self->ERROR(
            q{openid.claimed_id is present without openid.identity});
    }
    elsif ( !$claimed_id && $identity ) {
        return $self->ERROR(
            q{openid.identity is present without openid.claimed_id});
    }
    elsif ( !$claimed_id ) {

        my $service = OpenID::Lite::RelyingParty::Discover::Service->new;
        $service->add_type(SERVER_2_0);
        $service->add_uri( $self->params->get('op_endpoint') );
        $self->service($service);
        return 1;
    }

    if ( $self->has_service ) {
        unless ( $self->_verify_discovery_single( $self->service, $to_match ) ) {
            return unless $claimed_id;
            return unless $self->_discover_and_verify( $claimed_id, [$to_match] )
        }
    }
    else {
        $self->_discover_and_verify( $claimed_id, [$to_match] )
            or return;
    }

    if ( $self->service->claimed_identifier ne $to_match->claimed_identifier )
    {
        my $copied = $self->service->copy();
        $copied->claimed_identifier( $to_match->claimed_identifier );
        $self->service($copied);
    }

    return 1;
}

sub _verify_discovery_results {
    my $self = shift;
    if ( $self->params->is_openid1 ) {
        $self->_verify_discovery_results_openid1()
            or return;
    }
    elsif ( $self->params->is_openid2 ) {
        $self->_verify_discovery_results_openid2()
            or return;
    }
    else {
        return $self->ERROR(q{No reached});
    }
}

sub _check_nonce {
    my $self = shift;
    my ( $nonce, $server_url );
    if ( $self->params->is_openid1 ) {
        $nonce
            = $self->params->get_extra('rp_nonce');   # TODO: get extra params
        $server_url = '';
    }
    elsif ( $self->params->is_openid2 ) {
        $nonce = $self->params->get('response_nonce');
        $server_url = $self->has_service ? $self->service->url : undef;
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

    if ( $self->store
        && !$self->store->use_nonce( $server_url, $timestamp, $unique ) )
    {
        return $self->ERROR(
            sprintf q{Nonce already used or out of range: "%s"}, $nonce );
    }

    return 1;
}

sub _check_signature {

    my $self = shift;

    my $assoc;
    my $server_url = $self->service->url;

    if ( $self->store ) {
        my $assoc_handle = $self->params->get('assoc_handle');
        $assoc = $self->store->get_association( $server_url, $assoc_handle );
    }

    if ( !$assoc ) {
        return $self->_check_auth();
    }
    else {
        if ( $assoc->is_expired ) {
            return $self->ERROR(q{Association expired});
        }
        else {
            my $secret     = $assoc->secret;
            my $assoc_type = $assoc->type;
            my $method
                = OpenID::Lite::SignatureMethods->select_method($assoc_type);
            return $self->ERROR( sprintf q{Bad signature in response from %s},
                $server_url )
                unless $method->verify( $secret, $self->params );
        }
        return 1;
    }
}

sub _check_auth {
    my $self   = shift;
    my $params = $self->_create_check_auth_request()
        or return;
    my $server_url = $self->service->url;
    my $res_params
        = $self->_direct_communication->send_request( $server_url, $params )
            or return $self->ERROR(q{Failed direct-communication, 'checkauth' request});
    return $self->_process_check_auth_response($res_params);
}

sub _process_check_auth_response {
    my ( $self, $res_params ) = @_;
    my $is_valid          = $res_params->get('is_valid') || 'false';
    my $invalidate_handle = $res_params->get('invalidate_handle');
    my $server_url        = $self->service->url;
    if ($invalidate_handle) {
        if ( $self->store ) {
            $self->store->remove_association( $server_url,
                $invalidate_handle );
        }
    }

    if ( $is_valid ne 'true' ) {
        return $self->ERROR(
            sprintf
                q{Server %s responds that check_authentication call is not valid.},
            $server_url,
        );
    }
    return 1;
}

sub _create_check_auth_request {
    my $self       = shift;
    my $ca_message = $self->params->copy();
    $ca_message->set( mode => CHECK_AUTHENTICATION );
    return $ca_message;

}

sub _build__discoverer {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover->new(
        agent => $self->agent, );
}

sub _build__direct_communication {
    my $self = shift;
    return OpenID::Lite::RelyingParty::DirectCommunication->new(
        agent => $self->agent, );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

