package OpenID::Lite::Role::ParamBuilder;

use Mouse::Role;

requires 'SETUP_PARAMS';

use OpenID::Lite::Params;

sub build_param {
    my $self = shift;
    my $params = OpenID::Lite::Params->new;
    $self->SETUP_PARAMS($params);
    return $params;
}

1;

