package OpenID::Lite::SignatureMethod;

use Mouse;
use OpenID::Lite::Params;

has 'association' => (
    is => 'ro',
    isa => 'OpenID::Lite::Association',
);

sub sign {
    my ( $self, $params ) = @_;
    my $signed = $params->get('signed'); 
    return unless $singed;
    my @signed = split /,/, $signed;

    my $signed_params = OpenID::Lite::Params->new;
    for my $field ( @signed ) {
        $signed_params->set( $field, $params->get($field) );
    }
    my $key = $signed_params->to_key_value();
    return $self->_hmac_hash( $key );
}

sub _hmac_hash {
    my ( $self, $key ) = @_;
    die "Abstract Method.";
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;
