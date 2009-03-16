package OpenID::Lite::Provider::Response::InDirect;

use Any::Moose;
with 'OpenID::Lite::Provider::Response';

has '+needs_redirect' => (
    is      => 'ro',
    isa     => 'Bool',
    default => 1,
);

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

