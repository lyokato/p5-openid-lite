package OpenID::Lite::Provider::Handler::Factory;

use Any::Moose;
use OpenID::Lite::Constants::ModeType qw(:all);
use OpenID::Lite::Provider::Handler::Builders;
use List::MoreUtils qw(any);

sub create_handler_for {
    my ( $self, $req_params ) = @_;
    my $mode = $req_params->get('mode')
        or return $self->ERROR(q{Missing parameter, "mode".});
    my $builder
        = OpenID::Lite::Provider::Handler::Builders->select_builder($mode)
        or return $self->ERROR( sprintf q{Unknown mode, "%s".}, $mode );
    my $handler = $builder->build_from_params($req_params);
    return $handler;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

