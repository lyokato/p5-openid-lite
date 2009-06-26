package OpenID::Lite::Constants::ProviderResponseType;

use base 'Exporter';

our %EXPORT_TAGS = (
    all => [
        qw(
            DIRECT
            SETUP
            REDIRECT
            CHECKID_ERROR
            POSITIVE_ASSERTION
            REQUIRES_SETUP
            )
    ],
);
our @EXPORT_OK = map {@$_} values %EXPORT_TAGS;

use constant DIRECT             => 'direct';
use constant SETUP              => 'setup';
use constant REDIRECT           => 'redirect';
use constant CHECKID_ERROR      => 'checkid_error';
use constant POSITIVE_ASSERTION => 'positive_assertion';
use constant REQUIRES_SETUP     => 'requires_setup';

1;

