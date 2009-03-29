package OpenID::Lite::Role::AgentHandler;

use Any::Moose '::Role';

use LWP::UserAgent;

has 'agent' => ( is => 'rw', default => sub { LWP::UserAgent->new }, );

1;

