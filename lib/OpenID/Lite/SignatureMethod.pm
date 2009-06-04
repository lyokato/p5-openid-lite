package OpenID::Lite::SignatureMethod;

use Any::Moose;
use MIME::Base64 ();

sub sign {
    my ( $self, $secret, $params ) = @_;
    my $signed = $params->get('signed');
    return unless $signed;
    my @signed = split /,/, $signed;

    my $token = '';
    for my $field (@signed) {
        my $v = $params->get($field);
        $token .= "$field:$v\n";
    }
    my $hash = $self->hmac_hash($secret, $token);
    my $sig = MIME::Base64::encode_base64($hash);
    $sig =~ s/\s+//g;
    return $sig;
}

sub verify {
    my ( $self, $secret, $params ) = @_;
    my $sig = $params->get('sig');
    return unless $sig;
    #$sig =~ s/ /+/g;
    my $signed = $self->sign($secret, $params);
    return unless $signed;
    return $sig eq $signed;
}

sub hmac_hash {
    my ( $self, $secret, $key ) = @_;
    die "Abstract Method.";
}

sub hmac_hash_hex {
    my ( $self, $secret, $key ) = @_;
    die "Abstract Method.";
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

