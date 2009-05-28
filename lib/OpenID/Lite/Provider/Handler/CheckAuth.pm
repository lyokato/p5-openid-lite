package OpenID::Lite::Provider::Handler::CheckAuth;

use Any::Moose;
use OpenID::Lite::SignatureMethods;
use OpenID::Lite::Params;
use OpenID::Lite::Constants::ModeType qw(ID_RES);
with 'OpenID::Lite::Role::ErrorHandler';

has 'store' => (
    is => 'rw',
    #does => 'Storable',
    #default => sub { OpenID::Lite::Provider::Store::Null->new },
);


has 'check_nonce' => (
    is => 'ro',
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
    my $assoc = $self->store->find_private_association_by_handle($assoc_handle);
    if ( $assoc && !$assoc->is_expired ) {
        my $signature_method = OpenID::Lite::SignatureMethods->select($assoc->type);
        $is_valid = q{true} if $signature_method->verify($assoc->secret, $copied, $sig)
    }

    # XXX: what about openid1.X ?
    # if ( $req_params->is_openid2 )
    #     my $nonce = $req_params->get('response_nonce');
    #     my ($nonce_timestamp, $nonce_str) = split_nonce($nonce);
    #     unless ($self->check_nonce->($nonce_str, $nonce_timestamp)) {
    #         return $self->ERROR(q{Invalid nonce.});
    #     }
    # }

    # Remove handle which already used. This is for against replay attack.
    $self->store->remove_private_association_by_handle($assoc_handle);

    my $res_params = OpenID::Lite::Params->new;
    $res_params->set( ns       => $req_params->ns );
    $res_params->set( is_valid => $is_valid       );

    my $invalidate_handle = $copied->get('invalidate_handle');
    if ( $invalidate_handle ) {
        my $assoc = $self->store->find_association_by_handle($invalidate_handle);
        unless ( $assoc && !$assoc->is_expired ) {
            $res_params->set( invalidate_handle => $invalidate_handle );
        }
    }

    return $res_params;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

