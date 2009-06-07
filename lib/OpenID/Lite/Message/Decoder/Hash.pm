package OpenID::Lite::Message::Decoder::Hash;

use Any::Moose;
use OpenID::Lite::Message;

sub decode {
    my ( $self, $hash ) = @_;
    my $message = OpenID::Lite::Message->new;
    for my $key (%$hash) {
        if ( $key =~ /^openid\.(.+)$/ ) {
            $message->set( $1, $hash->{$key} );
        }
        elsif ( $key =~ /^openid\.(.+)\.(.+)$/ ) {
            my $ext_name = $1;
            my $ext_key  = $2;
            if ( $ext_name eq 'ns' ) {
                $message->register_extension_namespace( $ext_key,
                    $hash->{$key} );
            }
            else {
                $message->set_extension( $ext_name, $ext_key, $hash->{$key} );
            }
        }
        else {
            $message->set_extra( $key, $hash->{$key} );
        }
    }
    return $message;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


