package OpenID::Lite::Realm;

use Any::Moose;
use URI;
use List::MoreUtils qw(any none);

use OpenID::Lite::Provider::Discover;

has 'origin' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'scheme' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'host' => (
    is      => 'ro',
    isa     => 'Str',
    default => '',
);

has 'port' => (
    is  => 'ro',
    isa => 'Int',
);

has 'path' => (
    is      => 'ro',
    isa     => 'Str',
    default => '/',
);

has 'has_wildcard' => (
    is      => 'ro',
    isa     => 'Bool',
    default => 0,
);

my @TLDs = qw(com org net);

sub return_to_matches {
    my ( $class, $urls, $return_to ) = @_;
    for my $url (@$urls) {
        my $r = $class->parse($url);
        return 1
            if ( $r
            && !$r->has_wildcard
            && $r->validate_url($return_to) );
    }
    return 0;
}

sub get_allowed_return_urls {
    my ( $self, $url ) = @_;
    my $disco = OpenID::Lite::Provider::Discover->new();
    my $urls = $disco->discover($url, 1)
        or return;
}

sub verify_return_to {
    my ( $class, $realm, $return_to ) = @_;
    my $r = $class->parse($realm);
    return unless $r;
    my $disco_url      = $r->build_discovery_url();
    my $allowable_urls = $class->get_allowed_return_urls($disco_url);
    if ( $class->return_to_matches( $allowable_urls, $return_to ) ) {
        return 1;
    }
    return 0;
}

sub parse {
    my ( $class, $realm ) = @_;
    my $origin = $realm;
    my $found_wildcard = ( index( $realm, q{://*.} ) >= 0 ) ? 1 : 0;
    $realm =~ s/\*\.// if $found_wildcard;
    if ( !$found_wildcard && $realm =~ m|^https?\://\*/$| ) {
        my $scheme = ( split( ':', $realm ) )[0];
        my $port = $scheme eq 'http' ? 80 : 443;
        return $class->new(
            origin       => $origin,
            scheme       => $scheme,
            host         => '',
            port         => $port,
            has_wildcard => 1,
            path         => '/',
        );
    }
    my $parts = $class->_parse($realm);
    return unless $parts;
    my ( $scheme, $host, $port, $path ) = @$parts;
    if ( $path && index( $path, q{#} ) >= 0 ) {
        return;
    }
    return if ( any { $_ eq $scheme } qw(http https) );
    return $class->new(
        origin       => $origin,
        scheme       => $scheme,
        host         => $host,
        port         => $port,
        path         => $path,
        has_wildcard => $found_wildcard,
    );
}

sub _parse {
    my ( $class, $url ) = @_;

    # return if is_invalid($url);
    my $u    = URI->new($url);
    my $path = $u->path;
    $path .= sprintf q{?%s}, $u->query    if $u->query;
    $path .= sprintf q{#%s}, $u->fragment if $u->fragment;
    return [ $u->scheme || '', $u->host || '', $u->port || '', $path ];
}

sub check_url {
    my ( $class, $realm, $url ) = @_;
    my $r = $class->parse($realm);
    return ( $r && $r->validate_url($url) ) ? 1 : 0;
}

sub check_sanity {
    my ( $class, $realm ) = @_;
    my $r = $class->parse($realm);
    return ( $r && $r->is_sain() ) ? 1 : 0;
}

sub build_discovery_url {
    my $self = shift;
    if ( $self->has_wildcard ) {
        my $port
            = ( $self->port && ( $self->port == 80 || $self->port == 443 ) )
            ? sprintf ":%d", $self->port
            : '';
        return sprintf q{%s://www.%s%s%s},
            $self->scheme,
            $self->host,
            $port,
            $self->path;
    }
    else {
        return $self->origin;
    }
}

sub is_sane {
    my $self = shift;
    return 1 if $self->host eq 'localhost';
    my @host_parts = split( '.', $self->host );

    return 0 unless @host_parts > 1;
    return 0 if ( any { $_ eq '' } @host_parts );

    my $tld = $host_parts[-1];
    return 0 if ( none { $tld eq $_ } @TLDs );

    if ( $self->has_wildcard ) {
        if ( length($tld) == 2 && length( $host_parts[-2] ) <= 3 ) {
            return @host_parts > 2;
        }
    }

    return 1;
}

sub validate_url {
    my ( $self, $url ) = @_;
    my $parts = ref($self)->_parse($url);
    my ( $scheme, $host, $port, $path ) = @$parts;

    return 0 unless $self->scheme eq $scheme;
    return 0 unless $self->port == $port;
    return 0 if ( index( $host, q{*} ) >= 0 );

    my $s_host = $self->host;
    if ( !$self->has_wildcard ) {
        return 0 if $s_host ne $host;
    }
    elsif ($s_host ne ''
        && $host =~ /\.$s_host$/
        && $host ne $s_host )
    {
        return 0;
    }

    if ( $path ne $self->path ) {
        my $realm_path_length = length( $self->path );
        my $prefix = substr( $path, 0, $realm_path_length );

        return 0 if $self->path ne $prefix;
        my $allowed = ( index( $path, q{?} ) >= 0 ) ? q{&} : q{?/};

        return (
            index( $allowed, substr( $path, length($path), 1 ) ) >= 0
                || index( $allowed,
                substr( $self->path, $realm_path_length, 1 ) ) >= 0
        ) ? 1 : 0;
    }

    return 1;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

