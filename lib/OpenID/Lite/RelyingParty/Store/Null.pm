package OpenID::Lite::RelyingParty::Store::Null;

use Any::Moose;
with 'OpenID::Lite::Role::Storable';

sub store_association {
    return;
}

sub get_association {
    return;
}

sub remove_association {
    return 1;
}

sub cleanup_associations {
    return 0;
}

sub use_nonce {
    return 1;
}

sub cleanup_nonces {
    return 0;
}


no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
