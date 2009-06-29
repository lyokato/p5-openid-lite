package OpenID::Lite::Realm;

use Any::Moose;
use URI;
use List::MoreUtils qw(any none);

use OpenID::Lite::Provider::Discover;
use OpenID::Lite::Util::URI;

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

my @TLDs = qw(
      ac ad ae aero af ag ai al am an ao aq ar arpa as asia at
      au aw ax az ba bb bd be bf bg bh bi biz bj bm bn bo br bs bt
      bv bw by bz ca cat cc cd cf cg ch ci ck cl cm cn co com coop
      cr cu cv cx cy cz de dj dk dm do dz ec edu ee eg er es et eu
      fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gov gp gq
      gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in info int
      io iq ir is it je jm jo jobs jp ke kg kh ki km kn kp kr kw
      ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mil
      mk ml mm mn mo mobi mp mq mr ms mt mu museum mv mw mx my mz
      na name nc ne net nf ng ni nl no np nr nu nz om org pa pe pf
      pg ph pk pl pm pn pr pro ps pt pw py qa re ro rs ru rw sa sb
      sc sd se sg sh si sj sk sl sm sn so sr st su sv sy sz tc td
      tel tf tg th tj tk tl tm tn to tp tr travel tt tv tw tz ua
      ug uk us uy uz va vc ve vg vi vn vu wf ws xn--0zwm56d
      xn--11b5bs3a9aj6g xn--80akhbyknj4f xn--9t4b11yi5a
      xn--deba0ad xn--g6w251d xn--hgbk6aj7f53bba
      xn--hlcj6aya9esc7a xn--jxalpdlp xn--kgbechtv xn--zckzah ye
      yt yu za zm zw
);

sub return_to_matches {
    my ( $class, $urls, $return_to ) = @_;
    $return_to ||= '';
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
        my $scheme = ( split( /\:/, $realm ) )[0];
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
    return if ( none { $_ eq $scheme } qw(http https) );
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
    $url = OpenID::Lite::Util::URI->normalize($url)
        or return;
    return unless OpenID::Lite::Util::URI->is_uri($url);
    my $u = URI->new($url);
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
    return ( $r && $r->is_sane() ) ? 1 : 0;
}

sub build_discovery_url {
    my $self = shift;
    if ( $self->has_wildcard ) {
        my $port
            = ( $self->port && $self->port != 80 && $self->port != 443 )
            ? sprintf(":%d", $self->port)
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
    my @host_parts = split( /\./, $self->host );
    return 0 if scalar(@host_parts) == 0;
    return 0 if ( any { $_ eq '' } @host_parts );

    my $tld = $host_parts[-1];
    return 0 if ( none { $tld eq $_ } @TLDs );
    return 0 if scalar(@host_parts) == 1;

    if ( $self->has_wildcard ) {
        if ( length($tld) == 2 && length( $host_parts[-2] ) <= 3 ) {
            return @host_parts > 2 ? 1 : 0;
        }
    }

    return 1;
}

sub validate_url {
    my ( $self, $url ) = @_;
    my $parts = ref($self)->_parse($url)
        or return 0;
    my ( $scheme, $host, $port, $path ) = @$parts;

    return 0 unless $self->scheme eq $scheme;
    return 0 unless $self->port == $port;
    return 0 if ( index( $host, q{*} ) >= 0 );

    my $s_host = $self->host;
    if ( !$self->has_wildcard ) {
        return 0 if $s_host ne $host;
    }
    elsif ($s_host ne ''
        && $host !~ /\.$s_host$/
        && $host ne $s_host )
    {
        return 0;
    }

    if ( $path ne $self->path ) {
        my $path_length = length( $self->path );
        my $prefix = substr( $path, 0, $path_length );

        return 0 if $self->path ne $prefix;
        my $allowed = ( index( $self->path, q{?} ) >= 0 ) ? q{&} : q{?/};

        return (
        index( $allowed, substr( $self->path, -1 ) ) >= 0
     || index( $allowed, substr( $path, $path_length, 1 ) ) >= 0
        ) ? 1 : 0;
    }

    return 1;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

