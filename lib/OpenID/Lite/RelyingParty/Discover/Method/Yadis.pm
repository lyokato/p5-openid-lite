package OpenID::Lite::RelyingParty::Discover::Method::Yadis;
use Any::Moose;
extends 'OpenID::Lite::RelyingParty::Discover::Method::Base';

use OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis;
use OpenID::Lite::RelyingParty::Discover::Parser::Yadis;

override '_build__fetcher' => sub {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis->new(
        agent => $self->agent );
};

override '_build__parser' => sub {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover::Parser::Yadis->new;
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

