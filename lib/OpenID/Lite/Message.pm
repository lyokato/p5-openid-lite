package OpenID::Lite::Message;

use URI;
use URI::Escape ();
use Storable ();
use List::MoreUtils qw(any);

use OpenID::Lite::Constants::Namespace qw(SIGNON_1_0 SIGNON_1_1 SPEC_2_0);
use OpenID::Lite::Message::Decoder;

my $REQUEST_DECODER = OpenID::Lite::Message::Decoder->new;

sub new {
    my ( $class, %params ) = @_;
    my $self = bless {
        _params               => {},
        _extension_params     => {},
        _extra_params         => {},
        _extension_namespaces => {},
    }, $class;
    return $self;
}

sub copy {
    my $self = shift;
    my $class = ref $self;
    my $copied = Storable::dclone($self);
    return bless $copied, $class;
}

sub register_extension_namespace {
    my ( $self, $ext_name, $ext_ns ) = @_;
    $self->{_extension_namespaces}{$ext_name} = $ext_ns;
}

sub get {
    my ( $self, $key ) = @_;
    if ($key =~ /^([^.]+)\.([^.]+)$/) {
        my $ext_name = $1;
        my $ext_key  = $2;
        if ( $ext_name eq 'ns' ) {
            return exists $self->{_extension_namespaces}{$ext_key}
                ? $self->{_extension_namespaces}{$ext_key}
                : undef;;
        } else {
            return $self->get_extension($ext_name, $ext_key);
        }
    } else {
        return exists $self->{_params}{$key}
            ? $self->{_params}{$key}
            : undef;
    }
}

sub get_ns_alias {
    my ( $self, $ns ) = @_;
    for my $alias ( keys %{ $self->{_extension_namespaces} } ) {
        return $alias if $ns eq $self->{_extension_namespaces}{$alias};
    }
    return;
}

sub has_key {
    my ( $self, $key ) = @_;
    return exists $self->{_params}{$key};
}

sub get_extension {
    my ( $self, $ext_name, $key ) = @_;
    return (   exists $self->{_extension_params}{$ext_name}
            && exists $self->{_extension_params}{$ext_name}{$key} )
        ? $self->{_extension_params}{$ext_name}{$key}
        : undef;
}

sub get_extra {
    my ( $self, $key ) = @_;
    return exists $self->{_extra_params}{$key}
        ? $self->{_extra_params}{$key}
        : undef;
}

sub get_keys {
    my $self = shift;
    my @keys = keys %{ $self->{_params} };
    return \@keys;
}

sub get_extension_keys {
    my $self = shift;
    my $alias = shift;
    my @keys = keys %{ $self->{_extension_params}{$alias} };
    return \@keys;
}

sub get_extension_args {
    my $self = shift;
    my $alias = shift;
    return unless exists $self->{_extension_params}{$alias};
    return $self->{_extension_params}{$alias};
}

sub get_extra_keys {
    my $self = shift;
    my @keys = keys %{ $self->{_extra_params} };
    return \@keys;
}

sub set {
    my ( $self, $key, $value ) = @_;
    return unless ( defined $key && defined $value );
    if ($key =~ /^([^.]+)\.([^.]+)$/) {
        my $ext_name = $1;
        my $ext_key  = $2;
        if ($ext_name eq 'ns') {
            $self->register_extension_namespace($ext_key, $value);
        } else {
            $self->set_extension($ext_name, $ext_key, $value);
        }
    } else {
        $self->{_params}{$key} = $value;
    }
}

sub set_extension {
    my ( $self, $ext_name, $key, $value ) = @_;
    $self->{_extension_params}{$ext_name}{$key} = $value;
}

sub set_extra {
    my ( $self, $key, $value ) = @_;
    if ( defined $key && defined $value ) {
        if (ref $value eq 'ARRAY') {
            $self->{_extra_params}{$key} = @$value > 1 ? $value : $value->[0];
        } else {
            $self->{_extra_params}{$key} = $value
        }
    }

}

sub from_key_value {
    my ( $class, $body ) = @_;
    my $params = $class->new;
    for my $line ( split /\n/, $body ) {
        my ($key, $value) = split /:/, $line, 2;
        $params->set( $key, $value );
    }
    return $params;
}

sub from_request {
    my ( $class, $request ) = @_;
    return $REQUEST_DECODER->decode($request);
}

sub to_key_value {
    my $self = shift;

    #$self->set( ns => SIGNON_1_0 ) unless $self->get('ns');
    return join(
        "\n",
        map( sprintf( q{%s:%s}, $_, $self->{_params}{$_} ),
            sort keys %{ $self->{_params} } )
    )."\n";
}

sub to_post_body {
    my $self = shift;

    #$self->set( ns => SIGNON_1_0 ) unless $self->get('ns');
    my $params = $self->to_hash;
    return join(
        "&",
        map( sprintf( q{%s=%s},
                URI::Escape::uri_escape_utf8($_),
                URI::Escape::uri_escape_utf8( $params->{$_} ) ),
            sort keys %{ $params } )
    );
}

sub to_url {
    my ( $self, $uri ) = @_;

    #$self->set( ns => SIGNON_1_0 ) unless $self->get('ns');
    $uri = URI->new($uri) unless ref $uri eq 'URI';
    $uri->query_form( %{ $self->to_hash } );
    return $uri;
}

sub to_hash {
    my $self = shift;
    my %params = map { ( sprintf( q{openid.%s}, $_ ), $self->{_params}{$_} ) }
        keys %{ $self->{_params} };
    for my $ext_name ( keys %{ $self->{_extension_namespaces} } ) {
        my $key = sprintf( q{openid.ns.%s}, $ext_name );
        my $value = $self->{_extension_namespaces}{$ext_name};
        $params{$key} = $value;
    }
    for my $ext_name ( keys %{ $self->{_extension_params} } ) {
        my $ext_hash = $self->{_extension_params}{$ext_name};
        for my $ext_key ( keys %$ext_hash ) {
            my $key = sprintf( q{openid.%s.%s}, $ext_name, $ext_key );
            my $value = $ext_hash->{$ext_key};
            $params{$key} = $value;
        }
    }
    for my $key ( keys %{ $self->{_extra_params} } ) {
        $params{$key} = $self->{_extra_params}{$key};
    }
    return \%params;
}

sub set_signed {
    my $self = shift;
    my @keys = grep { $_ ne q{sig} } keys %{ $self->{_params} };
    for my $ext_name ( keys %{ $self->{_extension_namespaces} } ) {
        push(@keys, sprintf(q{ns.%s}, $ext_name));
        for my $ext_key ( keys %{ $self->{_extension_params}{$ext_name} } ) {
            push(@keys, sprintf(q{%s.%s},$ext_name, $ext_key));
        }
    }
    @keys = grep { $self->get($_) } @keys;
    push(@keys, q{signed});
    $self->set( signed => join(',', sort @keys));
}

sub is_openid1 {
    my $self = shift;
    my $ns   = $self->get('ns');
    return ( !$ns || any { $ns eq $_ } ( SIGNON_1_1, SIGNON_1_0 ) );
}

sub is_openid2 {
    my $self = shift;
    my $ns   = $self->get('ns');
    return ( $ns && $ns eq SPEC_2_0 );
}

1;
