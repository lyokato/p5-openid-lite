package OpenID::Lite::RelyingParty::DirectCommunication;

use Any::Moose;
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::ErrorHandler';

use HTTP::Request;
use OpenID::Lite::Message;

sub send_request {
    my ( $self, $url, $params ) = @_;
    my $req = HTTP::Request->new( POST => $url );
    $req->header( 'Content-Type' => q{application/x-www-form-urlencoded} );
    $req->content( $params->to_post_body );
    my $res = $self->agent->request($req);
    if ($res->is_success) {
        my $params = OpenID::Lite::Message->from_key_value($res->content);
        return $params;
    }
    return $self->ERROR($res->status_line);
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

