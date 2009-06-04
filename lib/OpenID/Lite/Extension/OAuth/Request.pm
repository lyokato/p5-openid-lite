package OpenID::Lite::Extension::OAuth::Request;

use Any::Moose;
extends 'OpenID::Lite::Extension::Request';

use constant OAUTH_NS => q{http://specs.openid.net/extensions/oauth/1.0};
use constant OAUTH_NS_ALIAS => q{oauth};

has 'consumer' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'scope' => (
    is  => 'ro',
    isa => 'Str',
);

override 'append_to_params' => sub {
    my ( $self, $params ) = @_;
    $params->register_extension_namespace( OAUTH_NS_ALIAS, OAUTH_NS );
    $params->set_extension( OAUTH_NS_ALIAS, 'consumer', $self->consumer );
    $params->set_extension( OAUTH_NS_ALIAS, 'scope',    $self->scope )
        if $self->scope;
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

