package OpenID::Lite::RelyingParty::Store::OnMemory;

use Any::Moose;
use OpenID::Lite::Nonce;
with 'OpenID::Lite::Role::Storable';

has 'associations' => (
    is      => 'ro',
    isa     => 'HashRef',
    default => sub { {}, },
);

has 'nonces' => (
    is      => 'ro',
    isa     => 'HashRef',
    default => sub { {}, },
);

sub store_association {
    my ( $self, $server_url, $assoc ) = @_;
    my $assocs = $self->associations->{$server_url}||{};
    $assocs->{ $assoc->handle } = $assoc->copy();
    $self->associations->{$server_url} = $assocs;
}

sub get_association {
    my ( $self, $server_url, $handle ) = @_;
    my $assocs = $self->associations->{$server_url}||{};
    my $assoc;
    if ($handle) {
        $assoc = $assocs->{$handle};
    }
    else {
        my @sorted = sort { $a->issued <=> $b->issued } values %$assocs;
        $assoc = $sorted[-1];
    }
    return $assoc;
}

sub remove_association {
    my ( $self, $server_url, $handle ) = @_;
    my $assocs = $self->associations->{$server_url}||{};
    return delete $assocs->{$handle} ? 1 : 0;
}

sub cleanup_associations {
    my $self  = shift;
    my $count = 0;
    for my $server_url ( keys %{ $self->associations } ) {
        my $assocs = $self->associations->{$server_url};
        for my $handle ( keys %$assocs ) {
            my $assoc = $assocs->{$handle};

            # if ($assoc->expires_in == 0) {
            if ( $assoc->is_expired ) {
                delete $assocs->{$handle};
                $count++;
            }
        }
    }
    return $count;
}

sub use_nonce {
    my ( $self, $server_url, $timestamp, $salt ) = @_;
    return 0 if ( abs($timestamp - time()) > OpenID::Lite::Nonce->skew );
    my $nonce = join('', $server_url, $timestamp, $salt);
    return 0 if exists $self->nonces->{$nonce};
    $self->nonces->{$nonce} = $timestamp;
    return 1;
}


sub cleanup_nonces {
    my $self = shift;
    my $count = 0;
    my $now = time();
    for my $nonce ( keys %{ $self->nonces } ) {
        my $timestamp = $self->nonces->{$nonce};
        if ( abs($now - $timestamp) > OpenID::Lite::Nonce->skew ) {
            delete $self->nonces->{$nonce};
            $count++;
        }
    }
    return $count;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

