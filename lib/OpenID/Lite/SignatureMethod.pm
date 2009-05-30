package OpenID::Lite::SignatureMethod;

use Any::Moose;
use OpenID::Lite::Message;

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
    return $self->_hmac_hash($secret, $key);
}

sub verify {
    my ( $self, $secret, $params, $sig ) = @_;
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

