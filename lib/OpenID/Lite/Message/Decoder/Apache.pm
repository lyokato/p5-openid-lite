package OpenID::Lite::Message::Decoder::Apache;

use Any::Moose;
use OpenID::Lite::Message;
extends 'OpenID::Lite::Message::Decoder::Hash';

override 'decode' => sub {
    my ( $self, $req ) = @_;
    my %data = $req->args;
    return super(\%data);
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

