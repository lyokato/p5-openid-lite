package OpenID::Lite::Role::ErrorHandler;

use Mouse::Role;

has '_errstr' => (
    is  => 'rw',
    isa => 'Str',
);

sub ERROR {
    my ( $self, $msg ) = @_;
    $self->_errstr( $msg || '' );
    return;
}

sub errstr {
    shift->_errstr;
}

1;

