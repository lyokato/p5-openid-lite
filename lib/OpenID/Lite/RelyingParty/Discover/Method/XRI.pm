package OpenID::Lite::RelyingParty::Discover::Method::XRI;
use Any::Moose;
extends 'OpenID::Lite::RelyingParty::Discover::Method::Base';

use OpenID::Lite::RelyingParty::Discover::Fetcher::XRI;
use OpenID::Lite::RelyingParty::Discover::Parser::XRI;

use OpenID::Lite::Constants::Namespace qw(
    SERVER_2_0
    SIGNON_2_0
    SIGNON_1_1
    SIGNON_1_0
);

override 'discover' => sub {
    my ( $self, $identifier ) = @_;
        my @services;
        for
        my $service_type ( SERVER_2_0, SIGNON_2_0, SIGNON_1_1, SIGNON_1_0 )
    {
        my $services
            = super( $identifier, { service_type => $service_type } );
        next
            unless ($services && @$services > 0);
        push @services, @$services;
    }
    return $self->ERROR( sprintf q{No Service Found for %s},
        $identifier->as_string )
        unless @services > 0;
    return \@services;
};

override '_build__fetcher' => sub {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover::Fetcher::XRI->new(
        agent => $self->agent );
};

override '_build__parser' => sub {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover::Parser::XRI->new;
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

