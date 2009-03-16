package OpenID::Lite::Handler::Builders;

use Any::Moose;
use OpenID::Lite::Provider::Handler::Association::Builder;
use OpenID::Lite::Provider::Handler::CheckID::Builder;
use OpenID::Lite::Provider::Handler::CheckAuth::Builder;

use OpenID::Lite::Constants::ModeType qw(:all);

# flyweight pattern

# dispatch table
my %builders = (
ASSOCIATION() =>
    OpenID::Lite::Provider::Handler::Association::Builder->new,
CHECKID_SETUP() =>
    OpenID::Lite::Provider::Handler::CheckID::Builder->new,
CHECK_AUTHENTICATION() =>
    OpenID::Lite::Provider::Handler::CheckAuth::Builder->new,
);
$builders{ CHECKID_IMMEDIATE() } = $builders{ CHECKID_SETUP() };

sub select_builder {
    my ( $class, $mode ) = @_;
    return $builders{$mode};
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

