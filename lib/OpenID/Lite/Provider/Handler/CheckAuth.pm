package OpenID::Lite::Provider::Handler::CheckAuth;

use Any::Moose;
use OpenID::Lite::SignatureMethods;
use OpenID::Lite::Message;
use OpenID::Lite::Nonce;
use OpenID::Lite::Provider::Response;
use OpenID::Lite::Constants::ProviderResponseType qw(:all);
use OpenID::Lite::Constants::ModeType qw(ID_RES);
use OpenID::Lite::Constants::Namespace qw(:all);
with 'OpenID::Lite::Role::ErrorHandler';

has 'check_nonce' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return 1; }
    }
);

has 'assoc_builder' => (
    is  => 'ro',
    isa => 'OpenID::Lite::Provider::AssociationBuilder',
);

sub handle_request {
    my ( $self, $req_params ) = @_;

    my $copied = $req_params->copy();
    $copied->set( mode => ID_RES );

    my $ns = $copied->get('ns');

    my $assoc_handle = $copied->get('assoc_handle');
    return $self->_build_error( $req_params,
        q{Missing parameter, "assoc_handle".}, $ns )
        unless $assoc_handle;

    my $sig = $copied->get('sig');
    return $self->_build_error( $req_params, q{Missing parameter, "sig".}, $ns)
        unless $sig;

    my $is_valid = q{false};
    my $assoc    = $self->assoc_builder->build_from_handle(
        $assoc_handle => { dumb => 1, } );
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
    $res_params->set( ns       => $ns );
    $res_params->set( is_valid => $is_valid );

    my $invalidate_handle = $copied->get('invalidate_handle');
    if ($invalidate_handle) {
        my $assoc
            = $self->assoc_builder->build_from_handle( $invalidate_handle, { dumb => 0 } );
        unless ( $assoc && !$assoc->is_expired ) {
            $res_params->set( invalidate_handle => $invalidate_handle );
        }
    }

    return OpenID::Lite::Provider::Response->new(
        type       => DIRECT,
        req_params => $req_params,
        res_params => $res_params,
    );
}

sub _build_error {
    my ( $self, $req_params, $msg, $ns ) = @_;
    $ns ||= SIGNON_2_0;
    my $error = OpenID::Lite::Message->new();
    $error->set( ns    => $ns );
    $error->set( error => $msg );
    my $res = OpenID::Lite::Provider::Response->new(
        type       => DIRECT,
        req_params => $req_params,
        res_params => $error,
    );
    return $res;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

