package OpenID::Lite::Constants::ModeType;

use strict;
use warnings;

use base 'Exporter';

our %EXPORT_TAGS = (
    all => [
        qw(
            ASSOCIATION
            CHECKID_IMMEDIATE
            CHECKID_SETUP
            ID_RES
            SETUP_NEEDED
            CANCEL
            CHECK_AUTHENTICATION
            ERROR_MODE
            )
    ],
);
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant ASSOCIATION          => 'associate';
use constant CHECKID_IMMEDIATE    => 'checkid_immediate';
use constant CHECKID_SETUP        => 'checkid_setup';
use constant ID_RES               => 'id_res';
use constant SETUP_NEEDED         => 'setup_needed';
use constant CANCEL               => 'cancel';
use constant CHECK_AUTHENTICATION => 'check_authentication';
use constant ERROR_MODE           => 'error';

1;

