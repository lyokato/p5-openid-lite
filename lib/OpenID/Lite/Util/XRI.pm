package OpenID::Lite::Util::XRI;

use strict;
use warnings;

my @XRI_AUTHORITIES = qw[! = @ + $ (];


sub identifier_scheme {
    my ( $class, $identifier ) = @_;
}

sub make_xri {
    my ( $class, $xri ) = @_;
    if ( $xri =~ /^xri:\/\// ) {
        $xri = sprintf q{xri://%s}, $xri;
    }
    return $xri;
}

sub remove_scheme {
    my ( $class, $xri ) = @_;
    if ( $xri =~ /^xri:\/\/(.*)$/ ) {
        $xri = $1;
    }
    return $xri;
}

sub root_authority {
    my ( $class, $xri ) = @_;
    $xri = $class->remove_scheme($xri);
    my $authority = (split('/', $xri, 2))[0];

    my $root;
    if ($authority =~ /^(\([^\)]*\))/) {
        $root = $1;
    } elsif ($authority =~ /^([\!\=\@\+\$\(])/) {
        $root = $1;
    } else {
        $root = (split /[!*]/, $authority)[0];
    }
    return $root;
}

sub provider_is_authoritative {
    my ( $class, $provider_id, $canonical_id ) = @_;
}

1;

