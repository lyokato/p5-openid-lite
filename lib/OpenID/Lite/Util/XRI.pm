package OpenID::Lite::Util::XRI;

use strict;
use warnings;

my @XRI_AUTHORITIES = qw[! = @ + $ (];

use List::MoreUtils qw(any);
use URI::Escape;

sub identifier_scheme {
    my ( $class, $identifier ) = @_;
    if ( $identifier
        && length($identifier) > 0 )
    {
        my $first = substr( $identifier, 0, 1 );
        return q{xri}
            if ( $identifier =~ /^xri:\/\//
            || any { $first eq $_ } @XRI_AUTHORITIES );
    }
    return q{uri};
}

sub to_iri_normal {
    my ( $class, $xri ) = @_;
    $xri = sprintf( q{xri://%s}, $xri ) if $xri !~ /^xri\:\/\//;
    return $class->escape_for_iri($xri);
}

sub escape_for_iri {
    my ( $class, $xri ) = @_;
    $xri =~ s/%/%25/g;
    $xri =~ s/(\(.*?\))/$class->_escape_for_iri_match($1)/eg;
    return $xri;
}

sub _escape_for_iri_match {
    my ( $class, $matched ) = @_;
    $matched =~ s/([\/\?\#])/URI::Escape::uri_escape_utf8($1)/eg;
    return $matched;
}

sub to_url_normal {
    my ( $class, $xri ) = @_;
    return $class->iri_to_url( $class->to_iri_normal($xri) );
}

sub iri_to_url {
    my ( $class, $iri ) = @_;
    return $iri;
}

sub make_xri {
    my ( $class, $xri ) = @_;
    if ( $xri =~ /^xri:\/\// ) {
        $xri = sprintf q{xri://%s}, $xri;
    }
    return $xri;
}

sub root_authority {
    my ( $class, $xri ) = @_;
    $xri = substr($xri, 6) if (index($xri, q{xri://}) == 0);
    my $authority = ( split( /\//, $xri, 2 ) )[0];

    my $root;
    if ( $authority =~ /^(\([^\)]*\))/ ) {
        $root = $1;
    }
    elsif ( $authority =~ /^([\!\=\@\+\$\(])/ ) {
        $root = $1;
    }
    else {
        $root = ( split /[!*]/, $authority )[0];
    }
    return $class->make_xri($root);
}

sub provider_is_authoritative {
    my ( $class, $provider_id, $canonical_id ) = @_;
    return unless ($provider_id && $canonical_id);
    my $lastbang = rindex($canonical_id, '!');
    return 0 if $lastbang < 0;
    my $parent = substr($canonical_id, 0, $lastbang);
    return ( $parent eq $provider_id );
}

1;

