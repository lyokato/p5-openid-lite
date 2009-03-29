package OpenID::Lite::RelyingParty::Discover::Method::HTML;

use Any::Moose;
extends 'OpenID::Lite::RelyingParty::Discover::Method::Base';

use OpenID::Lite::RelyingParty::Discover::Fetcher::HTML;
use OpenID::Lite::RelyingParty::Discover::Parser::HTML;

override '_build__fetcher' => sub {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover::Fetcher::HTML->new(
        agent => $self->agent );
};

override '_build__parser' => sub {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover::Parser::HTML->new;
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

