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

=head1 NAME

OpenID::Lite::Agent::Dump - agent for debug

=head1 SYNOPSIS

    my $rp = OpenID::Lite::RelyingParty->new( agent => OpenID::Lite::Agent::Dump->new );

=head1 DESCRIPTION

This is just a decorator of LWP::UserAgent.
Dump the request and response object for each request.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
