package OpenID::Lite::SignatureMethod;

use Any::Moose;
use OpenID::Lite::Message;
use MIME::Base64 ();

sub sign {
    my ( $self, $secret, $params ) = @_;
    my $signed = $params->get('signed');
    return unless $signed;
    my @signed = split /,/, $signed;

    my $signed_params = OpenID::Lite::Message->new;
    for my $field (@signed) {
        $signed_params->set( $field, $params->get($field) );
    }
    my $key = $signed_params->to_key_value();
    my $hash = $self->_hmac_hash($secret, $key);
    my $sig = MIME::Base64::encode_base64($hash);
    $sig =~ s/\s+//g;
    return $sig;
}

sub verify {
    my ( $self, $secret, $params ) = @_;
    my $sig = $params->get('sig');
    return unless $sig;
    my $signed = $self->sign($secret, $params);
    return unless $signed;
    return $sig eq $signed;
}

sub _hmac_hash {
    my ( $self, $secret, $key ) = @_;
    die "Abstract Method.";
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

