package OpenID::Lite::Provider::AssociationBuilder;

use Any::Moose;
use Digest::SHA;
use String::Random;
use OpenID::Lite::Association;
use OpenID::Lite::SignatureMethods;
with 'OpenID::Lite::Role::ErrorHandler';

has 'server_secret' => (
    is      => 'ro',
    isa     => 'Str',
    default => q{secret},
);

has 'secret_lifetime' => (
    is      => 'ro',
    isa     => 'Int',
    default => 86400,
);

#has 'secret_gen_interval' => (
#    is      => 'ro',
#    isa     => 'Int',
#    default => 86400,
#);
#
#has 'get_server_secret' => (
#    is      => 'ro',
#    isa     => 'CodeRef',
#    default => sub {
#        sub {
#            my $sec_time = shift;
#            my $secret = '';
#            return $secret;
#        }
#    },
#);
#

sub build_association {
    my $self     = shift;
    my %opts     = @_;
    my $type     = $opts{type};
    my $dumb     = $opts{dumb} || 0;
    my $lifetime = $opts{lifetime} || $self->secret_lifetime;

    my $signature_method
        = OpenID::Lite::SignatureMethods->select_method($type)
        or return $self->ERROR( sprintf q{Invalid assoc_type "%s"}, $type );

    my $now      = time();
    #my $sec_time = $now - ( $now % $self->secret_gen_interval );
    #my $s_sec    = $self->get_server_secret->($sec_time)
    #    || $self->server_secret;
    my $s_sec = $self->server_secret;

    my $random = String::Random->new;
    my $nonce = $random->randregex( sprintf '[a-zA-Z0-9]{%d}', 20 );
    $nonce = sprintf( q{STLS.%s}, $nonce ) if $dumb;

    my $handle = sprintf( q{%d:%s:%s}, $now, $type, $nonce );
    $handle
        .= ":"
        . substr( $signature_method->hmac_hash_hex( $handle, $s_sec ), 0,
        10 );
    my $c_sec = $self->secret_of_handle( $handle, $dumb, 1 )
        or return;

    my $assoc = OpenID::Lite::Association->new(
        secret     => $c_sec,
        handle     => $handle,
        type       => $type,
        expires_in => $lifetime,
        issued     => $now
    );
    return $assoc;
}

sub build_from_handle {
    my ( $self, $handle, $opts ) = @_;

    my $dumb     = $opts->{dumb}     || 0;
    my $lifetime = $opts->{lifetime} || $self->secret_lifetime;
    my ( $time, $type, $nonce, $nonce_sig80 ) = split( /:/, $handle );
    return $self->ERROR(q{not found proper time,type,nonce and nonce_sig80})
        unless $time =~ /^\d+$/ && $type && $nonce && $nonce_sig80;

    my $secret = $self->secret_of_handle( $handle, $dumb )
        or return;

    return OpenID::Lite::Association->new(
        secret     => $secret,
        handle     => $handle,
        type       => $type,
        issued     => $time,
        expires_in => $lifetime,
    );

}

sub secret_of_handle {
    my ( $self, $handle, $dumb, $no_verify ) = @_;
    my ( $time, $type, $nonce, $nonce_sig80 ) = split( /:/, $handle );
    return $self->ERROR(q{not found proper time,type,nonce and nonce_sig80})
        unless $time =~ /^\d+$/ && $type && $nonce && $nonce_sig80;
    return $self->ERROR(q{nonce is invalid for dumb-mode})
        if $dumb && $nonce !~ /^STLS\./;
    my $signature_method
        = OpenID::Lite::SignatureMethods->select_method($type)
        or return $self->ERROR( sprintf q{Invalid assoc_type, "%s"}, $type );

    #my $sec_time = $time - ( $time % $self->secret_gen_interval );
    #my $s_sec = $self->get_server_secret->($sec_time)
    #    || $self->server_secret;
    my $s_sec = $self->server_secret;

    length($nonce) == ( $dumb ? 25 : 20 )
        or return $self->ERROR(q{Invalid nonce length});
    length($nonce_sig80) == 10
        or return $self->ERROR(q{Invalid nonce_sig80 length});

    return $self->ERROR(q{Failed to verify nonce_sig80.})
        unless $no_verify
            || $nonce_sig80 eq substr(
                $signature_method->hmac_hash_hex(
                    sprintf( q{%d:%s:%s}, $time, $type, $nonce ), $s_sec
                ),
                0, 10
            );
    return $signature_method->hmac_hash( $handle, $s_sec );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

