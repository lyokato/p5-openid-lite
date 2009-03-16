package OpenID::Lite::Provider::Handler::CheckID;

use Any::Moose;
use OpenID::Lite::Constants::Namespace qw(IDENTIFIER_SELECT);
use OpenID::Lite::Constants::ModeType qw(CHECKID_IMMEDIATE CHECKID_SETUP);
use OpenID::Lite::Types qw(AssocHandle);

has 'assoc_handle' => (
    is       => 'rw',
    required => 1,
    isa      => AssocHandle,
);
has 'claimed_id' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);
has 'return_to' => (
    is => 'rw',
    isa => 'Str',
    required => 1,
);
has 'realm' => (
    is  => 'rw',
    isa => 'Str',
);

has 'op_endpoint' => (
    is => 'rw',
    isa => 'Str',
    required => 1,
);

has 'immediate' => (
    is       => 'rw',
    isa      => 'Bool',
    required => 1,
    default  => 0,
);

has 'mode' => (
    is  => 'rw',
    isa => 'Str',
);

sub BUILD {
    my ( $self, $params ) = @_;
    $self->claimed_id( $self->identity ) unless $self->claimed_id;
    # XXX: todo - validate realm
    $self->realm( $self->return_to )     unless $self->realm;
    $self->mode( $self->immediate ? CHECKID_IMMEDIATE : CHECKID_SETUP );
}

sub handle_request {
    my ( $self, $req_params ) = @_;

    #XXX: move to builder?
    unless ( $self->return_to ) {
        return $self->ERROR();
    }
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

