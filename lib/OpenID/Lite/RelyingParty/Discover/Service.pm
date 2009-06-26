package OpenID::Lite::RelyingParty::Discover::Service;

use Any::Moose;
use OpenID::Lite::Constants::Namespace
    qw(SERVER_2_0 SPEC_2_0 SPEC_1_0 SIGNON_2_0 SIGNON_1_1 SIGNON_1_0);
use List::MoreUtils qw(any none);

has 'uris' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [] },
);

has 'types' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [] },
);

has 'claimed_identifier' => (
    is  => 'rw',
    isa => 'Str',
);

has 'op_local_identifier' => (
    is  => 'rw',
    isa => 'Str',
);

my @PRIORITY_ORDER = ( SERVER_2_0, SIGNON_2_0, SIGNON_1_1, SIGNON_1_0 );

has 'type_priority' => (
    is      => 'rw',
    isa     => 'Int',
    default => sub {$#PRIORITY_ORDER}
);

sub copy {
    my $self   = shift;
    my $class  = ref($self);
    my $copied = $class->new;
    my $uris   = $self->uris;
    $copied->add_uri($_) for @$uris;
    my $types = $self->types;
    $copied->add_type($_) for @$types;
    $copied->claimed_identifier( $self->claimed_identifier )
        if $self->claimed_identifier;
    $copied->op_local_identifier( $self->op_local_identifier )
        if $self->op_local_identifier;
    return $copied;
}

sub find_local_identifier {
    my $self = shift;
    return $self->op_local_identifier || $self->claimed_identifier;
}

sub url {
    my $self = shift;
    my $uris = $self->uris;
    return $uris->[0] || '';
}

sub is_op_identifier {
    my $self  = shift;
    my $types = $self->types;
    return ( any { $_ eq SERVER_2_0 } @$types );
}

sub preferred_namespace {
    my $self = shift;
    $self->requires_compatibility_mode ? SPEC_1_0 : SPEC_2_0;
}

sub requires_compatibility_mode {
    my $self  = shift;
    my $types = $self->types;
    return ( none { $_ eq SERVER_2_0 || $_ eq SIGNON_2_0 } @$types );
}

sub has_uri {
    my ( $self, $uri ) = @_;
    return ( any { $_ eq $uri } @{ $self->uris } );
}

sub add_uri {
    my ( $self, $uri ) = @_;
    my $uris = $self->uris;
    push @$uris, $uri;
}

sub add_uris {
    my $self = shift;
    $self->add_uri($_) for @_;
}

sub add_type {
    my ( $self, $type ) = @_;
    my $types = $self->types;
    for ( my $i = 0; $i < @PRIORITY_ORDER; $i++ ) {
        if (   $type eq $PRIORITY_ORDER[$i]
            && $self->type_priority > $i )
        {
            $self->type_priority($i);
        }
    }
    push @$types, $type;
}

sub add_types {
    my $self = shift;
    $self->add_type($_) for @_;
}

sub has_type {
    my ( $self, $type ) = @_;
    return ( any { $_ eq $type } @{ $self->types } );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME

OpenID::Lite::Relyingparty::Discover::Service - Discovered information

=head1 SYNOPSIS

    $service->url;
    $service->claimed_identifier
    $service->op_local_identifier
    $service->copy;
    $service->find_local_identifier;
    $service->is_op_identifier;
    $service->preferred_namespace;
    $service->requires_compatibility_mode;
    $service->has_type(  );
    $service->add_type();
    $service->has_uri();
    $service->add_uri();

=head1 DESCRIPTION

This class's object represents discovered information.

=head1 METHODS

=head2 new

    my $service = OpenID::Lite::RelyingParty::Discover::Service->new;

=head2 url

Returns service endpoint url.

    my $service_endpoint_url = $service->url;

=head2 add_type

Add a type of service the OP provides.

    use OpenID::Lite::Constants::Namespace qw( SERVER_2_0 SIGNON_2_0 );

    $service->add_type( SERVER_2_0 );
    $service->add_type( SIGNON_2_0 );

=head2 has_type

Check if the OP provides indicated type of service.

    use OpenID::Lite::Constants::Namespace qw( SERVER_2_0 );
    $service->has_type( SERVER_2_0 );

=head2 add_uri

Add endpoint uri

    $service->has_uri(q{http://yourapp.com/openid/endpoint});

=head2 has_uri

Check if the service includes indicated uri.

    if ( $service->has_uri( $endpoint_uri ) ) {
        ...
    }

=head2 claimed_identifier

Return claimed identitifier if it has.
(When discovery is carried out with claimed_id)

    my $claimed_id = $service->claimed_identifier;

=head2 op_local_identifier

Return op local identitifier if it has.
(When discovery is carried out with claimed_id and the response which OP returns includes LocalID)

    my $op_local_identifier = $service->op_local_identifier;

=head2 find_local_identifier

Returns op_local_identfier if it found.
Or return claimed id.

    my $identity = $service->find_local_identifier;


=head2 copy

    my $copied_service = $service->copy();

=head2 is_op_identifier

Return true if this is for OP identifier
(When discovery is carried out with OP identifier)

    if ( $service->is_op_identifier ) {
        ...
    }

=head2 preferred_namespace

Return proper namespace for openid.ns

=head2 requires_compatibility_mode

If the endpoint accepts only OpenID 1.x version protocol,
return true.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
