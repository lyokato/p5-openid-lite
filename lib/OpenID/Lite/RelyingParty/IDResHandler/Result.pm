package OpenID::Lite::RelyingParty::IDResHandler::Result;

use Mouse;

has 'status' => (
    is  => 'ro',
    isa => '',
);

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

