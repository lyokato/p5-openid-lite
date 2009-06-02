package OpenID::Lite::RelyingParty::CheckID::Result;

use Any::Moose;

has 'type' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'message' => (
    is      => 'ro',
    isa     => 'Str',
    default => '',
);

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

