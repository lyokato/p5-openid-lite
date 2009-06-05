package OpenID::Lite::SessionHandler::DH;

use Any::Moose;
extends 'OpenID::Lite::SessionHandler';

use OpenID::Lite::DH;
use MIME::Base64;

has '_secret_length' => (
    is       => 'ro',
    isa      => 'Int',
    required => 1,
);

has '_dh' => (
    is         => 'ro',
    lazy_build => 1,
);

override 'set_request_params' => sub {
    my ( $self, $service, $params ) = @_;
    my $dh = $self->_dh;
    my $dh_consumer_public = $dh->generate_public();
    $params->set( dh_consumer_public => $dh_consumer_public );
    $params->set( session_type => $self->_session_type );
    return $params;
};

override 'extract_secret' => sub {
    my ( $self, $params ) = @_;
    my $dh_server_public = $params->get('dh_server_public')
        or return $self->ERROR(q{Missing parameter, "dh_server_public".});
    my $enc_mac_key = $params->get('enc_mac_key')
        or return $self->ERROR(q{Missing parameter, "enc_mac_key".});
    my $dh = $self->_dh;
    my $dh_sec = $dh->compute_public($dh_server_public);
    my $secret
        = MIME::Base64::decode_base64($enc_mac_key) ^ $self->_hash($dh_sec);

    my $secret_length = length $secret;
    unless ( $secret_length == $self->_secret_length ) {
        return $self->ERROR(
            sprintf q{Secret length should be "%d", but got "%d"},
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

    my $dh =  OpenID::Lite::DH->new;
    if ( $dh_modulus || $dh_gen ) {
        $dh->p($dh_modulus);
        $dh->g($dh_gen);
        $dh->generate_keys();
    }

    my $dh_consumer_public = $req_params->get('dh_consumer_public')
        or return $self->ERROR(q{Missing parameter, "dh_consumer_public".});
    my $dh_sec      = $dh->compute_public($dh_consumer_public);
    my $enc_mac_key = MIME::Base64::encode_base64(
        $association->secret ^ $self->_hash($dh_sec) );
    $enc_mac_key =~ s/\s+//g;
    $res_params->set( enc_mac_key => $enc_mac_key );

    my $dh_server_public = $dh->generate_public();

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
    my $dh = OpenID::Lite::DH->new;
    return $dh;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

