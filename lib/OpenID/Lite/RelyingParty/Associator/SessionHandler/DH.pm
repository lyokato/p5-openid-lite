package OpenID::Lite::RelyingParty::Associator::SessionHandler::DH;

use Mouse;
extends 'OpenID::Lite::RelyingParty::Associator::SessionHandler';

use Crypt::DH::GMP;
use MIME::Base64 ();

has 'dh_modulus' => (
    is  => 'rw',
    isa => 'Str',
    default =>
        q{155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443},
    trigger => sub {
        my $self = shift;
        $self->_use_default_dh(0);
        $self->_dh( $self->_build__dh() );
    },
);

has 'dh_gen' => (
    is      => 'rw',
    isa     => 'Str',
    default => q{2},
    trigger => sub {
        my $self = shift;
        $self->_use_default_dh(0);
        $self->_dh( $self->_build__dh() );
    },
);

has '_use_default_dh' => (
    is      => 'rw',
    isa     => 'Bool',
    default => 1,
);

has '_dh' => (
    is         => 'rw',
    lazy_build => 1,
);

override 'set_request_params' => sub {
    my ( $self, $service, $params ) = @_;

# num2bin needs Math::BigInt?
# unless ( $self->_use_default_dh ) {
#    $params->set( dh_modules => MIME::Base64::encode_base64(num2bin($self->dh_modulus)) );
#    $params->set( dh_gen     => MIME::Base64::encode_base64(num2bin($self->dh_gen)) );
# }
    $params->set( dh_consumer_public =>
            MIME::Base64::encode_base64( $self->_dh->pub_key_twoc ) );
    unless ( $service->requires_compatibility_mode ) {
        $params->set( session_type => $self->_session_type );
    }
    return $params;
};

override 'extract_secret' => sub {
    my ( $self, $params ) = @_;
    my $dh_server_public = $params->get('dh_server_public');
    my $enc_mac_key      = $params->get('enc_mac_key');
    my $dh_sec           = $self->_dh->compute_secret_twoc($dh_server_public);
    my $secret
        = MIME::Base64::decode_base64($enc_mac_key) ^ $self->_hash($dh_sec);
    return $secret;
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

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

