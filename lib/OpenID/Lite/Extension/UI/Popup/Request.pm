package OpenID::Lite::Extension::UI::Popup::Request;

use Any::Moose;
extends 'OpenID::Lite::Extension::Request';

use OpenID::Lite::Extension::UI qw(UI_NS UI_NS_ALIAS UI_POPUP_NS);

has 'mode' => (
    is      => 'rw',
    isa     => 'Str',
    default => q{popup},
);

# RP should create popup to be 450 pixels wide and 500 pixels tall.
# The popup must have the address bar displayed.
# The popup must be in a standalone browser window.
# The contents of the popup must not be framed by the RP.
override 'append_to_params' => sub {
    my ( $self, $params ) = @_;
    $params->register_extension_namespace( UI_NS_ALIAS, UI_NS );
    $params->set_extension( UI_NS_ALIAS, 'mode', $self->mode );
};

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
