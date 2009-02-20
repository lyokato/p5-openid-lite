package OpenID::Lite::Identifier;

use strict;
use warnings;

use URI;

sub new {
    my $class = shift;
    bless {
        is_xri => 0,
        raw    => '',
    }, $class;
}

sub normalize {
    my ( $class, $uri ) = @_;
    my $self = $class->new;
    if ( $uri =~ /^xri:\/\/(.+)$/ ) {
        $self->{is_xri} = 1;
        $self->{raw}    = $1;
    }
    elsif ( $uri =~ /^[\=\@\+\$\!\)]/ ) {
        $self->{is_xri} = 1;
        $self->{raw}    = $uri;
    }
    else {
        $self->{is_xri} = 0;
        unless ( $uri =~ /^https?:\/\// ) {
            $uri = sprintf q{http://%s}, $uri;
        }
        # remove fragment
        $uri =~ s/\#.*$//;

        # XXX: todo
        # check if uri is correct.
        my $u = URI->new($uri)->canonical;
        my $path = $u->path || '/';
        $self->{raw} = ($u->port == 80 || $u->port == 443)
            ? sprintf(q{%s://%s%s}, $u->scheme, $u->host, $path)
            : sprintf(q{%s://%s:%d%s}, $u->scheme, $u->host, $u->port, $path);
    }
    return $self;
}

sub is_xri      { shift->{is_xri} }
sub is_http_uri { !shift->is_xri }
sub as_string   { shift->{raw} }

1;
