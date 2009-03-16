package OpenID::Lite::SessionHandler::DH;

use Any::Moose;
extends 'OpenID::Lite::SessionHandler';

use Crypt::DH::GMP;
use MIME::Base64;

has 'dh_modulus' => (
    is  => 'rw',
    isa => 'Str',
    default =>
        q{155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443},
);

has 'dh_gen' => (
    is      => 'ro',
    isa     => 'Str',
    default => q{2},
);

has '_secret_length' => (
    is       => 'ro',
    isa      => 'Int',
    required => 1,
);

override 'set_request_params' => sub {
    my ( $self, $service, $params ) = @_;

    my $dh = $self->_build__dh();

# num2bin needs Math::BigInt?
# unless ( $self->_use_default_dh ) {
#    $params->set( dh_modules => MIME::Base64::encode_base64(num2bin($self->dh_modulus)) );
#    $params->set( dh_gen     => MIME::Base64::encode_base64(num2bin($self->dh_gen)) );
# }
    my $dh_consumer_public = MIME::Base64::encode_base64( $dh->pub_key_twoc );
    $dh_consumer_public =~ s/\s+//g;
    $params->set( dh_consumer_public => $dh_consumer_public );
    unless ( $service->requires_compatibility_mode ) {
        $params->set( session_type => $self->_session_type );
    }
    return $params;
};

override 'extract_secret' => sub {
    my ( $self, $params ) = @_;
    my $dh_server_public = $params->get('dh_server_public')
        or return $self->ERROR(q{Missing parameter, "dh_server_public".});
    my $enc_mac_key = $params->get('enc_mac_key')
        or return $self->ERROR(q{Missing parameter, "enc_mac_key".});
    my $dh     = $self->_build__dh();
    my $dh_sec = $dh->compute_key_twoc($dh_server_public);
    my $secret
        = MIME::Base64::decode_base64($enc_mac_key) ^ $self->_hash($dh_sec);

    my $secret_length = length $secret;
    unless ( $secret_length == $self->_secret_length ) {
        return $self->ERROR(
            sprintf q{Secret length should be "%d", but got "%s"},
            $self->_secret_length, $secret_length );
    }
    return $secret;
};

override 'set_response_params' => sub {
    my ( $self, $req_params, $res_params, $association ) = @_;

    my $dh_modulus = $req_params->get('dh_modulus');
    my $dh_gen     = $req_params->get('dh_gen');

    if ( ( !$dh_modulus && $dh_gen ) || ( $dh_modulus && !$dh_gen ) ) {
        my $missing = $dh_modulus ? 'dh_gen' : 'dh_modulus';
        return $self->ERROR( sprintf q{Missing parameter, "%s".}, $missing );
    }

    my $dh = Crypt::DH::GMP->new;
    if ( $dh_modulus || $dh_gen ) {
        $dh->p($dh_modulus);
        $dh->g($dh_gen);
    }
    else {
        $dh->p( $self->dh_modulus );
        $dh->g( $self->dh_gen );
    }
    $dh->generate_keys();

    my $dh_consumer_public = $req_params->get('dh_consumer_public')
        or return $self->ERROR(q{Missing parameter, "dh_consumer_public".});
    my $dh_sec      = $dh->compute_key_twoc($dh_consumer_public);
    my $enc_mac_key = MIME::Base64::encode_base64(
        $association->secret ^ $self->_hash($dh_sec) );
    $enc_mac_key =~ s/\s+//g;
    $res_params->set( enc_mac_key => $enc_mac_key );

    my $dh_server_public = MIME::Base64::encode_base64( $dh->pub_key_twoc );
    $dh_server_public =~ s/\s+//g;

    $res_params->set( dh_server_public => $dh_server_public );

    $res_params->set( session_type => $self->_session_type );
};

sub _hash {
    my ( $self, $dh_sec ) = @_;
    die "abstract method";
    return $dh_sec;
}

sub _build__dh {
    my $self = shift;
    my $dh   = Crypt::DH::GMP->new;
    $dh->p( $self->dh_modulus );
    $dh->g( $self->dh_gen );
    $dh->generate_keys();
    return $dh;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

