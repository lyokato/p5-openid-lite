package OpenID::Lite::Message::Decoder::CGI;

use Any::Moose;
use OpenID::Lite::Message;

sub decode {
    my ( $self, $req ) = @_;
    my $message = OpenID::Lite::Message->new;
    my @param = $req->param;
    for my $key ( @param ) {
        my @values = $req->param( $key );
        if ( $key =~ /^openid\.(.+)$/ ) {
            $message->set( $1, $values[0] );
        }
        elsif ( $key =~ /^openid\.(.+)\.(.+)$/ ) {
            my $ext_name = $1;
            my $ext_key  = $2;
            if ( $ext_name eq 'ns' ) {
                $message->register_extension_namespace( $ext_key,
                    $values[0] );
            }
            else {
                $message->set_extension( $ext_name, $ext_key, $values[0] );
            }
        }
        else {
            $message->set_extra( $key, \@values );
        }
    }
    return $message;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


