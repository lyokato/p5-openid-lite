package OpenID::Lite::RelyingParty::Discover::FetchResult;

use Mouse;
use MouseX::Types::URI qw(Uri);

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
    isa => Uri,
);

no Mouse;
__PACKAGE__->meta->make_immutable;
1;


