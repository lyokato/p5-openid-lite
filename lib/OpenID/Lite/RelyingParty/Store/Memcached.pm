package OpenID::Lite::RelyingParty::Store::Memcached;

use Any::Moose;

sub find_association_by_server_url {
    my ( $self, $server_url ) = @_;
}

sub save_association {
    my ( $self, $server_url, $association ) = @_;
}

sub find_association_by_handle {
    my ( $self, $assoc_handle ) = @_;
}


sub get {
    my ( $self, $key ) = @_;
}

sub set {
    my ( $self, $key, $value ) = @_;
}


no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;


