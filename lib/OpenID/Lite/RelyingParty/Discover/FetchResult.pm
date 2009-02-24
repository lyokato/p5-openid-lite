package OpenID::Lite::RelyingParty::Discover::FetchResult;

use Mouse;

has 'xrds' => (
    is => 'rw',
);

has 'content_type' => (
    is => 'rw',
    isa => 'Str',
);

has 'content' => (
    is => 'rw',
    isa => 'Str',
);

has 'normalized_identifier' => (
    is => 'rw',
    isa => 'Str',
);

has 'final_url' => (
    is => 'rw',
    isa => 'Str',
);

no Mouse;
__PACKAGE__->meta->make_immutable;
1;


