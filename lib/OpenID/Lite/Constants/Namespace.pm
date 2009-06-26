package OpenID::Lite::Constants::Namespace;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = (
    all => [
        qw(
            SPEC_2_0
            SPEC_1_0
            XRDS
            XRD_2_0
            SERVER_2_0
            SIGNON_2_0
            SIGNON_1_1
            SIGNON_1_0
            IDENTIFIER_SELECT
            RETURN_TO
            )
    ]
);
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant SPEC_2_0   => q{http://specs.openid.net/auth/2.0};
use constant SPEC_1_0   => q{http://openid.net/xmlns/1.0};
use constant XRDS       => q{xri://$xrds};
use constant XRD_2_0    => q{xri://$xrd*($v*2.0)};
use constant SERVER_2_0 => q{http://specs.openid.net/auth/2.0/server};
use constant SIGNON_2_0 => q{http://specs.openid.net/auth/2.0/signon};
use constant SIGNON_1_1 => q{http://openid.net/signon/1.1};
use constant SIGNON_1_0 => q{http://openid.net/signon/1.0};

use constant IDENTIFIER_SELECT =>
    q{http://specs.openid.net/auth/2.0/identifier_select};

use constant RETURN_TO => q{http://specs.openid.net/auth/2.0/return_to};

1;

=head1 NAME

OpenID::Lite::Constants::Namespace - Namespace constants

=head1 SYNOPSIS

    use OpenID::Lite::Constants::Namespace qw(:all);

or

    use OpenID::Lite::Constants::Namespace qw(SPEC_2_0 SERVER_2_0 SIGNON_2_0);

=head1 DESCRIPTION

This class provides constants represents namespaces that
is for OpenID service type.

=head1 CONSTANTS

=head2 SPEC_2_0

http://specs.openid.net/auth/2.0

=head2 SPEC_1_0

http://openid.net/xmlns/1.0

=head2 XRDS

xri://$xrds

=head2 XRD_2_0

xri://$xrd*($v*2.0)

=head2 SERVER_2_0

http://specs.openid.net/auth/2.0/server

=head2 SIGNON_2_0

use constant SIGNON_2_0 => q{http://specs.openid.net/auth/2.0/signon};

=head2 SIGNON_1_1

http://openid.net/signon/1.1

=head2 SIGNON_1_0

http://openid.net/signon/1.0

=head2 IDENTIFIER_SELECT

http://specs.openid.net/auth/2.0/identifier_select

=head2 RETURN_TO

http://specs.openid.net/auth/2.0/return_to

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
