package OpenID::Lite::Identifier;

use strict;
use warnings;

use overload
    q{""}    => sub { shift->as_string },
    fallback => 1;

use URI;
use OpenID::Lite::Util::URI;

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
    if ( $uri =~ /^xri:\/\/([\=\@\+\$\!\)].+)$/ ) {
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

        $uri = OpenID::Lite::Util::URI->normalize($uri);
        return unless OpenID::Lite::Util::URI->is_uri($uri);
        my $u = URI->new($uri)->canonical;
=pod
        my $path = $u->path || '/';
        $self->{raw}
            = ( $u->port == 80 || $u->port == 443 )
            ? sprintf( q{%s://%s%s}, $u->scheme, $u->host, $path )
            : sprintf( q{%s://%s:%d%s}, $u->scheme, $u->host, $u->port,
            $path );
=cut
        $u->path( $u->path || '/' );
        $u->port( undef ) if $u->port == 80 || $u->port == 443;
        $u->fragment( undef );
        $self->{raw} = $u->as_string;
    }
    return $self;
}

sub is_xri      { shift->{is_xri} }
sub is_http_uri { !shift->is_xri }
sub as_string   { shift->{raw} }

1;
