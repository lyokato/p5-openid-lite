package OpenID::Lite::Provider::Handler::CheckAuth;

use Any::Moose;
use OpenID::Lite::SignatureMethods;

has 'signed' => (
    is       => 'ro',
    isa      => 'OpenID::Lite::Params',
    required => 1,
);

sub handle_request {
    my ( $self, $req_params ) = @_;

    my $assoc_handle = $req_params->get('assoc_handle');
    my $signed       = $req_params->get('signed');

    my $association = $self->store->get_association_by_handle($assoc_handle);
    unless ( $association && !$association->is_expired ) {
        return $self->ERROR(q{});
    }

    my $method
        = OpenID::Lite::SignatureMethods->select_method( $association->type );
    my $is_valid_str
        = $method->verify( $association->secret, $self->signed, $signed )
        ? 'true'
        : 'false';

    my $res_params = OpenID::Lite::Params->new;
    $res_params->set( is_valid => $is_valid_str );

    my $response = OpenID::Lite::Provider::Response::Direct->new(
        params => $res_params );
    return $response;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

