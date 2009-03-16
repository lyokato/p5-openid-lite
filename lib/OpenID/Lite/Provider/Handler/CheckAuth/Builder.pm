package OpenID::Lite::Provider::Handler::CheckAuth::Builder;

use Any::Moose;
use OpenID::Lite::Provider::Handler::CheckAuth;
use OpenID::Lite::Constants::ModeType qw(ID_RES);
with 'OpenID::Lite::Role::ErrorHandler';

sub build_from_params {
    my ( $self, $params ) = @_;

    my $assoc_handle = $params->get('assoc_handle')
        or return $self - ERROR(q{Missing prameter, "assoc_handle".});
    my $sig = $params->get('sig')
        or return $self->ERROR(q{Missing parameter, "sig"});

    my $signed = $params->copy();
    if ( $signed->get('mode') ) {
        $signed->set( mode => ID_RES );
    }

    my $handler = OpenID::Lite::Provider::Handler::CheckAuth->new(
        signed => $signed,
    );

    return $handler;

}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

