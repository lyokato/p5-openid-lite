package OpenID::Lite::RelyingParty::Store::Null;

use Any::Moose;
with 'OpenID::Lite::Role::Storable';

sub store_association {

}

sub get_association {

}

sub remove_association {

}

sub cleanup_associations {

}

sub use_nonce {

}

sub cleanup_nonces {

}


no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
