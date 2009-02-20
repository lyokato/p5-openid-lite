package OpenID::Lite::RelyingParty::Discover;

use Mouse;
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::Discoverer';
with 'OpenID::Lite::Role::AgentHandler';

use OpenID::Lite::RelyingParty::Discover::Method::XRI;
use OpenID::Lite::RelyingParty::Discover::Method::URL;

sub discover {
    my ( $self, $identity ) = @_;
    my $disco = $self->create_method_for( $identity );
    return $disco->discover( $identity )
        || $self->ERROR( $disco->errstr );
}

# factory method
sub create_method_for {
    my ( $self, $identity ) = @_;
    my $disco
        = $identity->is_xri
        ? OpenID::Lite::RelyingParty::Discover::Method::XRI->new(
        agent => $self->agent )
        : OpenID::Lite::RelyingParty::Discover::Method::URL->new(
        agent => $self->agent );
    return $disco;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME 

OpenID::Lite::RelyingParty::Discover - Facade class for discovery.

=head1 SYNOPSIS

    use OpenID::Lite::RelyingParty::Discover;

    my $disco = OpenID::Lite::RelyingParty::Discover->new( agent => $agent );
    my $info = $disco->discover( $identity )
        or die $disco->errstr;
    my $url = $info->op_endpoint_url;

=head1 DESCRIPTION

=head1 METHODS

=head2 new

Constructor.

=head2 discover

Discover interface.
See also L<OpenID::Lite::Role::Discoverer>.
This returns L<OpenID::Lite::RelyingParty::Discover::DiscoveredInformation> object.

    my $info = $discover->discover( $identity );

=head2 create_method_for

Factory method.
Returns object which does Discoverer role.
See also L<OpenID::Lite::Role::Discoverer>.

    my $method = $discover->create_method_for( $identity );

=head2 errstr

Returns error string after this object failed discovery.

    $info = $discover->discover( $identity )
        or die $discover->errstr;

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
