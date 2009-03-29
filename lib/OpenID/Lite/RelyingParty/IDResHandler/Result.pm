package OpenID::Lite::RelyingParty::IDResHandler::Result;

use Any::Moose;

has 'status' => (
    is  => 'ro',
    isa => '',
);

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

