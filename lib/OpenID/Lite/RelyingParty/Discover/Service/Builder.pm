package OpenID::Lite::RelyingParty::Discover::Service::Builder;

use Any::Moose;

use List::MoreUtils qw(any);
use OpenID::Lite::RelyingParty::Discover::Service;
use OpenID::Lite::Constants::Namespace qw(
    SIGNON_2_0
    SIGNON_1_1
    SIGNON_1_0
    SERVER_2_0
    XRD_2_0
    SPEC_1_0
);

has 'claimed_identifier' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

sub build_services {
    my ( $self, $xrd ) = @_;
    my @service_nodes = $xrd->findnodes(q{*[local-name()='Service']});
    my @services;
    for my $service_elem (@service_nodes) {
        my $service = $self->build_service($service_elem)
            or next;
        push @services, $service;
    }
    return \@services;
}

sub build_service {
    my ( $self, $service_elem ) = @_;

    my @uri_nodes = $service_elem->findnodes(q{*[local-name()='URI']});

    # Schwartzian transform
    my @uris = map { $_->[0] }
        sort { $a->[1] <=> $b->[1] }
        map {
        [ $_->findvalue(q{text()}), $_->findvalue(q{@priority}) || 100 ]
        } @uri_nodes;

    #my @uris = map { $_->findvalue(q{text()}) }
    #    sort {
    #    ( $a->findvalue(q{@priority}) || 100 )
    #        <=> ( $b->findvalue(q{@priority}) || 100 )
    #    } @uri_nodes;

    my @type_nodes = $service_elem->findnodes(q{*[local-name()='Type']});
    my @types = map { $_->findvalue(q{text()}) } @type_nodes;

    return unless @uris > 0 && @types > 0;
    return
        unless (
        any {
                   $_ eq SERVER_2_0
                || $_ eq SIGNON_2_0
                || $_ eq SIGNON_1_1
                || $_ eq SIGNON_1_0;
        }
        @types
        );

    my $service = OpenID::Lite::RelyingParty::Discover::Service->new;
    $service->add_uris(@uris);
    $service->add_types(@types);

    unless ( $service->is_op_identifier ) {
        $service->claimed_identifier( $self->claimed_identifier );
        my $op_local_identifier;
        my $xpath_template
            = q{*[local-name()='%s' and namespace-uri()='%s']/text()};
        if ( any { $_ eq SIGNON_2_0 } @types ) {
            $op_local_identifier
                = $service_elem->findvalue( sprintf $xpath_template,
                'LocalID', XRD_2_0 );
        }
        if ( any { $_ eq SIGNON_1_1 || $_ eq SIGNON_1_0 } @types ) {
            $op_local_identifier
                = $service_elem->findvalue( sprintf $xpath_template,
                'Delegate', SPEC_1_0 );
        }

        $service->op_local_identifier($op_local_identifier)
            if $op_local_identifier;
    }
    return $service;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

