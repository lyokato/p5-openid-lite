package OpenID::Lite::Extension::PAPE::Request;

use Any::Moose;

extends 'OpenID::Lite::Extension::Request';

use OpenID::Lite::Extension::PAPE qw(
    PAPE_NS
    PAPE_NS_ALIAS
    PAPE_AUTH_MULTIFACTOR_NS
    PAPE_AUTH_MULTIFACTOR_PHYSICAL_NS
    PAPE_AUTH_PHISHING_RESISTANT_NS
);

has 'preferred_auth_policies' => (
    is      => 'ro',
    isa     => 'ArrayRef[Str]',
    default => sub { [] },
);

has 'max_auth_age' => (
    is  => 'ro',
    isa => 'Str',
);

override 'append_to_params' => sub {
    my ( $self, $params ) = @_;
    $params->register_extension_namespace( PAPE_NS_ALIAS, PAPE_NS );
    $params->set_extension( PAPE_NS_ALIAS, 'preferred_auth_policies',
        join( ' ', @{ $self->preferred_auth_policies } ) );
    $params->set_extension( PAPE_NS_ALIAS, 'max_auth_age',
        $self->max_auth_age )
        if defined $self->max_auth_age;
};

sub add_policy_url {
    my ( $self, $url ) = @_;
    if ( none { $_ eq $url } @{ $self->preferred_auth_policies } ) {
        push( @{ $self->preferred_auth_policies }, $url );
    }
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

