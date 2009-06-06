package OpenID::Lite::Agent::Paranoid;

use Any::Moose;
use HTTP::Date;
use LWPx::ParanoidAgent;

has '_agent' => (
    is         => 'ro',
    isa        => 'LWPx::ParanoidAgent',
    lazy_build => 1,
);

has 'blocked_hosts' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [] },
);

has 'whitelisted_hosts' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [] },
);

has 'https_debug' => (
    is      => 'ro',
    isa     => 'Bool',
    default => 0,
);

has 'https_ca_dir' => (
    is  => 'ro',
    isa => 'Str',
);

has 'https_ca_file' => (
    is  => 'ro',
    isa => 'Str',
);

has 'https_proxy' => (
    is  => 'ro',
    isa => 'Str',
);

has 'https_proxy_username' => (
    is  => 'ro',
    isa => 'Str',
);

has 'https_proxy_password' => (
    is  => 'ro',
    isa => 'Str',
);

has 'https_cert_file' => (
    is  => 'ro',
    isa => 'Str',
);

has 'https_key_file' => (
    is  => 'ro',
    isa => 'Str',
);

sub get {
    my ( $self, $url ) = @_;
    local $ENV{HTTPS_DEBUG}   = $self->https_debug   if $self->https_debug;
    local $ENV{HTTPS_CA_FILE} = $self->https_ca_file if $self->https_ca_file;
    local $ENV{HTTPS_CA_DIR}  = $self->https_ca_dir  if $self->https_ca_dir;
    local $ENV{HTTPS_CERT_FILE} = $self->https_cert_file
        if $self->https_cert_file;
    local $ENV{HTTPS_KEY_FILE} = $self->https_key_file
        if $self->https_key_file;
    local $ENV{HTTPS_VERSION} = $self->https_version if $self->https_version;
    local $ENV{HTTPS_PROXY}   = $self->https_proxy   if $self->https_proxy;
    local $ENV{HTTPS_PROXY_USERNAME} = $self->https_proxy_username
        if $self->https_proxy_username;
    local $ENV{HTTPS_PROXY_PASSWORD} = $self->https_proxy_password
        if $self->https_proxy_password;
    my $response = $self->_agent->get($url);
    return $self->_filter_response($response);
}

sub request {
    my ( $self, $request ) = @_;
    local $ENV{HTTPS_DEBUG}   = $self->https_debug   if $self->https_debug;
    local $ENV{HTTPS_CA_FILE} = $self->https_ca_file if $self->https_ca_file;
    local $ENV{HTTPS_CA_DIR}  = $self->https_ca_dir  if $self->https_ca_dir;
    local $ENV{HTTPS_CERT_FILE} = $self->https_cert_file
        if $self->https_cert_file;
    local $ENV{HTTPS_KEY_FILE} = $self->https_key_file
        if $self->https_key_file;
    local $ENV{HTTPS_VERSION} = $self->https_version if $self->https_version;
    local $ENV{HTTPS_PROXY}   = $self->https_proxy   if $self->https_proxy;
    local $ENV{HTTPS_PROXY_USERNAME} = $self->https_proxy_username
        if $self->https_proxy_username;
    local $ENV{HTTPS_PROXY_PASSWORD} = $self->https_proxy_password
        if $self->https_proxy_password;
    my $response = $self->_agent->request($request);
    return $self->_filter_response($response);
}

sub _filter_response {
    my ( $self, $response ) = @_;
    if ( $response->header('Client-SSL-Warning') ) {
        my $err = HTTP::Response->new( 403,
            q{Unauthorized access to no verified certification} );
        $err->header( 'Client-Date'    => HTTP::Date::time2str( time() ) );
        $err->header( 'Client-Warning' => 'Internal response' );
        $err->header( 'Content-Type'   => 'text/plain' );
        $err->content(q{403 Unauthorized access to blocked host});
        return $err;
    }
    return $response;
}

sub _build__agent {
    my $self = shift;
    return LWPx::ParanoidAgent->new(
        blocked_hosts     => $self->blocked_hosts,
        whitelisted_hosts => $self->whitelisted_hosts,
    );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

