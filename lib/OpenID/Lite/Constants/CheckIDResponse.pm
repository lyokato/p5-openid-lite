package OpenID::Lite::Constants::CheckIDResponse;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = (
    all => [
        qw(
        IS_SUCCESS
        IS_NOT_OPENID
        IS_ERROR
        IS_SETUP_NEEDED
        IS_CANCELED
        IS_INVALID
            )
    ],
);
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant IS_SUCCESS      => 'success';
use constant IS_NOT_OPENID   => 'not_openid';
use constant IS_ERROR        => 'error';
use constant IS_SETUP_NEEDED => 'setup_needed';
use constant IS_CANCELED     => 'canceled';
use constant IS_INVALID      => 'invalid';

1;

