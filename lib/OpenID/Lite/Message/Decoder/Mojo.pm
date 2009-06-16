package OpenID::Lite::Message::Decoder::Mojo;

use Any::Moose;
extends 'OpenID::Lite::Message::Decoder::Hash';

override 'decode' => sub {
    my ( $self, $request ) = @_;
    return super( $request->params->to_hash );
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


