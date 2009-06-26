package OpenID::Lite::Association;

use Any::Moose;

use OpenID::Lite::Types qw(AssocType SessionType);
use OpenID::Lite::Constants::AssocType qw(HMAC_SHA1 HMAC_SHA256);
use String::Random;
use MIME::Base64;

has 'handle' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'secret' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'type' => (
    is       => 'rw',
    isa      => AssocType,
    required => 1,
);

has 'expires_in' => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
);

has 'issued' => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
);

sub copy {
    my $self = shift;
    return ref($self)->new(
        handle     => $self->handle,
        secret     => $self->secret,
        type       => $self->type,
        expires_in => $self->expires_in,
        issued     => $self->issued,
    );
}

sub expires_at {
    my $self = shift;
    return ( $self->issued + $self->expires_in );
}

sub is_expired {
    my $self = shift;
    return ( $self->expires_at < time() );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME

OpenID::Lite::Association - Association class

=head1 SYNOPSIS

    $assoc->handle;
    $assoc->secret;
    $assoc->type;
    $assoc->expires_in;
    $assoc->issued;
    $assoc->expires_at;
    $assoc->is_expires;
    $assoc->copy;

=head1 DESCRIPTION

This class's object represents association that established between RP and OP.
You don't need to build association by yourself.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
