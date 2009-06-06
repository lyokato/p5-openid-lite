package OpenID::Lite::Agent::Dump;

use Any::Moose;
use LWP::UserAgent;
use Data::Dump qw(dump);

has '_agent' => (
    is => 'ro',
    default => sub { LWP::UserAgent->new, },
);

sub get {
    my ( $self, $url ) = @_;
    dump($url);
    my $response = $self->_agent->get($url);
    dump($response);
    return $response;
}

sub request {
    my ( $self, $request ) = @_;
    dump($request);
    my $response = $self->_agent->request($request);
    dump($response);
    return $response;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


