package OpenID::Lite::RelyingParty::Associator;

use Mouse;
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::Associator';

use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION DH_SHA1 DH_SHA256);

use OpenID::Lite::RelyingParty::Associator::Base;
use OpenID::Lite::RelyingParty::Associator::SessionHandler::NoEncryption;
use OpenID::Lite::RelyingParty::Associator::SessionHandler::DH::SHA1;
use OpenID::Lite::RelyingParty::Associator::SessionHandler::DH::SHA256;

sub associate {
    my ( $self, $service ) = @_;

    # TODO: cache control -> should be moved to RelyingParty.pm?
    # my $server_url = $service->url;
    # my $association = $self->store->find_association_for( $server_url );
    # if ( !$association || $association->is_expired ) {

    my $associator  = $self->create_method_for( $self->session_type );
    my $association = $associator->associate($service)
        or return $self->ERROR( $associator->errstr );

    #     $self->store->save_association( $server_url => $association );
    # }

    return $association;
}

# factory method
sub create_method_for {
    my ( $self, $type ) = @_;
    my $session_handler;
    if ( $type eq NO_ENCRYPTION ) {
        $session_handler
            = OpenID::Lite::RelyingParty::Associator::SessionHandler::NoEncryption
            ->new;
    }
    elsif ( $type eq DH_SHA1 ) {
        $session_handler
            = OpenID::Lite::RelyingParty::Associator::SessionHandler::DH::SHA1
            ->new;
    }
    elsif ( $type eq DH_SHA256 ) {
        $session_handler
            = OpenID::Lite::RelyingParty::Associator::SessionHandler::DH::SHA256
            ->new;
    }
    else {
        die "invalid session type";
    }
    my $associator = OpenID::Lite::RelyingParty::Associator::Base->new(
        agent           => $self->agent,
        assoc_type      => $self->assoc_type,
        session_handler => $session_handler,
    );
    return $associator;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME 

OpenID::Lite::RelyingParty::Associator - associator

=head1 SYNOPSIS

    use OpenID::Lite::RelyingParty::Associator;
    use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1);
    use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION);

    my $associator = OpenID::Lite::RelyingParty::Associator->new(
        agent        => LWPx::ParanoidAgent->new,
        assoc_type   => HMAC_SHA1,
        session_type => NO_ENCRYPTION,
    );
    my $association = $associator->associate( $service )
        or die $associator->errstr;

=head1 DESCRIPTION

=head1 METHODS 

=head2 new

Constructor.

=head2 associate

Associate interface.
See also L<OpenID::Lite::Role::Associator>.
This returns L<OpenID::Lite::RelyingParty::Association> object.

    my $association = $associator->associate( $service );

=head2 create_method_for

Factory method.
Returns object which does Associator role.
See also L<OpenID::Lite::Role::Associator>.

    my $method = $associator->create_method_for( $session_type );

=head2 errstr

Returns error string after this object failed association.

    my $association = $associator->associate( $service )
        or die $associator->errstr;

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
