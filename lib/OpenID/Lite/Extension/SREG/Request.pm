package OpenID::Lite::Extension::SREG::Request;

use Any::Moose;
use List::MoreUtils qw(any none);
use Carp ();

extends 'OpenID::Lite::Extension::Request';

has '_required' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [] },
);

has '_optional' => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { [] },
);

has 'policy_url' => (
    is  => 'rw',
    isa => 'Str',
);

my @SREG_FIELDS = qw(
    fullname
    nickname
    dob
    email
    gender
    postcode
    country
    language
    timezone
);

use constant SREG_NS_1_0   => q{http://openid.net/sreg/1.0};
use constant SREG_NS_1_1   => q{http://openid.net/extensions/sreg/1.1};
use constant SREG_NS_ALIAS => q{sreg};

override 'append_to_params' => sub {
    my ( $self, $params ) = @_;
    $params->register_extension_namespace( SREG_NS_ALIAS, SREG_NS_1_1 );

    my $required = $self->_required;
    $params->set_extension( SREG_NS_ALIAS, 'required',
        join( ',', @$required ) )
        if @$required > 0;
    my $optional = $self->_optional;
    $params->set_extension( SREG_NS_ALIAS, 'optional',
        join( ',', @$optional ) )
        if @$optional > 0;
    $params->set_extension( SREG_NS_ALIAS, 'policy_url', $self->policy_url )
        if $self->policy_url;
};

sub check_field_name {
    my ( $self, $field_name ) = @_;
    return ( $field_name && ( any { $_ eq $field_name } @SREG_FIELDS ) );
}

sub request_field {
    my ( $self, $field_name, $required ) = @_;
    $self->check_field_name($field_name)
        or Carp::confess( sprintf q{Invalid field-name for SREG, "%s"},
        $field_name );
    my $required_fields = $self->_required;
    my $optional_fields = $self->_optional;
    return if ( any { $_ eq $field_name } @$required_fields );
    if ( any { $_ eq $field_name } @$optional_fields ) {
        return unless $required;
        my @new_optional = grep { $_ ne $field_name } @$optional_fields;
        $optional_fields = \@new_optional;
        $self->_optional($optional_fields);
    }
    if ($required) {
        push( @$required_fields, $field_name );
    }
    else {
        push( @$optional_fields, $field_name );
    }
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;
