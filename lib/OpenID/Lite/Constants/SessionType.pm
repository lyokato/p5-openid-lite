package OpenID::Lite::Constants::SessionType;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = ( all => [qw(NO_ENCRYPTION DH_SHA1 DH_SHA256)] );
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant NO_ENCRYPTION => 'no-encryption';
use constant DH_SHA1       => 'DH-SHA1';
use constant DH_SHA256     => 'DH-SHA256';

1;


=head1 NAME

OpenID::Lite::Constants::SessionType - session type constants

=head1 SYNOPSIS

    use OpenID::Lite::Constants::SessionType qw(:all);

or

    use OpenID::Lite::Constants::SessionType qw(NO_ENCRYPTION DH_SHA1 DH_SHA256);

=head1 DESCRIPTION

This class provides constatns for each session type.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
