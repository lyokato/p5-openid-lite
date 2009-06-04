package OpenID::Lite::Extension::OAuth::Response;

use Any::Moose;
extends 'OpenID::Lite::Extension::Response';

has 'request_token' => ();
has 'scope' => ();

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

