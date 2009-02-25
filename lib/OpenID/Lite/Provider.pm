package OpenID::Lite::Provider;

use Mouse;
use OpenID::Lite::Params;

sub handle_request {
    my ($self, $request) = @_;
    my $params;
    if ( $request->method eq 'POST') {
        $params = OpenID::Lite::Params->from_key_value($request->content);
    } elsif ( $request->method eq 'GET' ) {
        $params = OpenID::Lite::Params->from_request($request->params);
    }
    my $mode = $params->get('mode');
    my $method = $self->create_method_for($mode);
    $method->handle_request($params);
}

sub create_method_for {
    my ( $self, $mode ) = @_;
    my $method;
    if ( $mode eq ASSOCIATION ) {
        $method = OpenID::Lite::Provider::Associator->new;
    } elsif ( $mode eq CHECKID_SETUP ) {

    } elsif ( $mode eq CHECKID_IMMEDIATE ) {

    } elsif ( $mode eq CHECK_AUTHENTICATION ) {

    }
    return $method;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;


