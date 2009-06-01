package OpenID::Lite::Provider::Handler::CheckAuth;

use Any::Moose;
use OpenID::Lite::SignatureMethods;
use OpenID::Lite::Message;
use OpenID::Lite::Nonce;
use OpenID::Lite::Provider::AssociationBuilder;
use OpenID::Lite::Constants::ModeType qw(ID_RES);
with 'OpenID::Lite::Role::ErrorHandler';

has 'check_nonce' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return 1; }
    }
);

has 'secret_lifetime' => (
    is      => 'ro',
    isa     => 'Int',
    default => 86400,
);

has 'server_secret' => (
    is  => 'ro',
    isa => 'Str',
);

has '_assoc_builder' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::Provider::AssociationBuilder',
    lazy_build => 1,
);

sub handle_request {
    my ( $self, $req_params ) = @_;

    my $copied = $req_params->copy();
    $copied->set( mode => ID_RES );

    my $assoc_handle = $copied->get('assoc_handle');
    return $self->ERROR(q{Missing parameter, "assoc_handle".})
        unless $assoc_handle;

    my $sig = $copied->get('sig');
    return $self->ERROR(q{Missing parameter, "sig".})
        unless $sig;

    my $is_valid = q{false};
    my $assoc = $self->_assoc_builder->build_from_handle( $assoc_handle => {
        dumb     => 1,
        lifetime => $self->secret_lifetime,
    } );
    if ( $assoc && !$assoc->is_expired ) {
        my $signature_method
            = OpenID::Lite::SignatureMethods->select_method( $assoc->type );
        $is_valid = q{true}
            if $signature_method->verify( $assoc->secret, $copied, $sig );
    }

# XXX: what about openid1.X ?
# if ( $req_params->is_openid2 )
#     my $nonce = $req_params->get('response_nonce');
#     my ($nonce_timestamp, $nonce_str) = OpenID::Lite::Nonce->split_nonce($nonce);
#     unless ($self->check_nonce->($nonce_str, $nonce_timestamp)) {
#         return $self->ERROR(q{Invalid nonce.});
#     }
# }

    my $res_params = OpenID::Lite::Message->new;
    $res_params->set( ns       => $req_params->ns );
    $res_params->set( is_valid => $is_valid );

    my $invalidate_handle = $copied->get('invalidate_handle');
    if ($invalidate_handle) {
        my $assoc
            = $self->store->find_association_by_handle($invalidate_handle);
        unless ( $assoc && !$assoc->is_expired ) {
            $res_params->set( invalidate_handle => $invalidate_handle );
        }
    }

    return $res_params;
}

sub _build__assoc_builder {
    my $self = shift;
    return OpenID::Lite::Provider::AssociationBuilder->new(
        server_secret => $self->server_secret,
    );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

