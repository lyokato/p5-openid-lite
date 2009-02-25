package OpenID::Lite::RelyingParty::DirectCommunication;

use Mouse;
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::ErrorHandler';

use HTTP::Request;
use OpenID::Lite::Params;

sub send_request {
    my ( $self, $url, $params ) = @_;
    my $req = HTTP::Request->new( POST => $url );
    $req->header( 'Content-Type' => q{application/x-www-form-urlencoded} );
    $req->content( $params->to_post_body );
    my $res = $self->agent->request($req);
    # TODO: SSL restriction
    use Data::Dump qw(dump);
    warn dump($res);
    if ($res->is_success) {
        my $params = OpenID::Lite::Params->from_key_value($res->content);
        return $params;
    }
    return $self->ERROR($res->status_line);
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME 

=head1 SYNOPSIS


=cut


