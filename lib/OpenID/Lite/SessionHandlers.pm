package OpenID::Lite::SessionHandlers;

use strict;
use warnings;

use OpenID::Lite::Constants::SessionType qw(:all);

use OpenID::Lite::SessionHandler::NoEncryption;
use OpenID::Lite::SessionHandler::DH::SHA1;
use OpenID::Lite::SessionHandler::DH::SHA256;

# dispatch table
my %handlers = (
    NO_ENCRYPTION() => OpenID::Lite::SessionHandler::NoEncryption->new,
    DH_SHA1()       => OpenID::Lite::SessionHandler::DH::SHA1->new,
    DH_SHA256()     => OpenID::Lite::SessionHandler::DH::SHA256->new,
);

sub select_session {
    my ( $class, $type ) = @_;
    return $handlers{$type};
}

1;

