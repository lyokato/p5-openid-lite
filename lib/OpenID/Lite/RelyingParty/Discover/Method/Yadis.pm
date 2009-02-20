package OpenID::Lite::RelyingParty::Discover::Method::Yadis;
use Mouse;
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

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

