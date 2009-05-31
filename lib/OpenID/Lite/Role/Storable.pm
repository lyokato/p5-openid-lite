package OpenID::Lite::Role::Storable;

use Any::Moose '::Role';

requires qw(
    store_association
    get_association
    remove_association
    use_nonce
    cleanup_nonces
    cleanup_associations
);

sub cleanup {
    my $self = shift;
    return ($self->cleanup_nonces, $self->cleanup_associations);
}


1;


