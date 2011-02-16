package OpenID::Lite::RelyingParty;

use Any::Moose;

use OpenID::Lite::Identifier;
use OpenID::Lite::Message;
use OpenID::Lite::RelyingParty::Discover;
use OpenID::Lite::RelyingParty::Associator;
use OpenID::Lite::RelyingParty::CheckID::Request;

use OpenID::Lite::RelyingParty::IDResHandler;
use OpenID::Lite::RelyingParty::Store::OnMemory;

use URI;
use Params::Validate;

has '_discoverer' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_associator' => (
    is         => 'ro',
    lazy_build => 1,
);

has '_id_res_handler' => (
    is         => 'ro',
    lazy_build => 1,
);

has 'session' => (
    is  => 'rw',
#    isa => 'HTTP::Session',
);

has 'store' => (
    is      => 'rw',
    does    => 'OpenID::Lite::Role::Storable',
    default => sub { OpenID::Lite::RelyingParty::Store::OnMemory->new },
);

with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';
with 'OpenID::Lite::Role::Associator';
with 'OpenID::Lite::Role::Discoverer';

sub begin {
    my ( $self, $user_suplied_identifier, $anonymous ) = @_;

    my $identifier = $self->normalize_identifier($user_suplied_identifier);
    return unless $identifier;

    my $services = $self->discover($identifier);
    return unless $services;

    my $service = $services->[0];

    $self->begin_without_discovery( $service, $anonymous );
}

sub begin_without_discovery {
    my ( $self, $service, $anonymous ) = @_;

    my $association = $self->associate($service) or return;

    #return unless $association;

    my %params = ( service => $service );
    $params{association} = $association if $association;
    $params{anonymous}   = 1            if $anonymous;

    my $checkid_req
        = OpenID::Lite::RelyingParty::CheckID::Request->new(%params);
    $self->last_requested_endpoint($service);

    return $checkid_req;
}

sub last_requested_endpoint {
    my ( $self, $endpoint ) = @_;
    return unless $self->session;
    if ($endpoint) {
        $self->session->set( 'openid.last_requested_endpoint', $endpoint );
    }
    else {
        $endpoint = $self->session->get('openid.last_requested_endpoint');
    }
    return $endpoint;
}

sub normalize_identifier {
    my ( $self, $user_suplied_identifier ) = @_;
    my $identifier
        = OpenID::Lite::Identifier->normalize($user_suplied_identifier);
    return $identifier
        ? $identifier
        : $self->ERROR( sprintf q{Invalid identifier: %s},
        $user_suplied_identifier );
}

sub discover {
    my ( $self, $identifier ) = @_;

    # execute discovery
    my $services = $self->_discoverer->discover($identifier)
        or return $self->ERROR( $self->_discoverer->errstr );
    return $self->ERROR( sprintf q{Service not found for identifier %s},
        $identifier )
        unless @$services > 0;

    # pick up op-identifier information if it exists
    my @op_identifiers = grep { $_->is_op_identifier } @$services;
    return \@op_identifiers if @op_identifiers > 0;

    # sorted by priority
    # we like 2.0 service endpoint rather than 1.X.
    my @sorted_services
        = sort { $a->type_priority <=> $b->type_priority } @$services;

    return \@sorted_services;
}

sub associate {
    my ( $self, $service ) = @_;
    my $server_url = $service->url;

    # find association related to passed server-url
    my $association = $self->store->get_association($server_url);

    # if there isn't available association,
    # it starts to negotiate with provider to obtain new association.
    if ( !$association || $association->is_expired ) {
        $association = $self->_associator->associate($service)
            or return $self->ERROR( $self->_associator->errstr );

        # if it finished successfully, save it.
        $self->store->store_association( $server_url => $association )
            if $association;
    }
    return $association;
}

sub complete {
    my ( $self, $request, $current_url ) = @_;
    my $params  = OpenID::Lite::Message->from_request($request);
    my $service = $self->last_requested_endpoint;
    my %args    = (
        current_url => $current_url,
        params      => $params,
    );
    $args{service} = $service if $service;
    my $result = $self->idres(%args);
    return $result;
}

sub idres {
    my $self = shift;
    my %args = Params::Validate::validate(
        @_,
        {   current_url => 1,
            params      => {
                isa => 'OpenID::Lite::Message',
            },
            service     => {
                isa      => 'OpenID::Lite::RelyingParty::Discover::Service',
                optional => 1
            },
        }
    );
    return $self->_id_res_handler->idres(%args)
        || $self->ERROR( $self->_id_res_handler->errstr );
}

sub _build__discoverer {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Discover->new( agent => $self->agent,
    );
}

sub _build__associator {
    my $self = shift;
    return OpenID::Lite::RelyingParty::Associator->new(
        agent        => $self->agent,
        assoc_type   => $self->assoc_type,
        session_type => $self->session_type,
    );
}

sub _build__id_res_handler {
    my $self = shift;
    return OpenID::Lite::RelyingParty::IDResHandler->new(
        agent => $self->agent,
        store => $self->store,
    );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME

OpenID::Lite::RelyingParty - OpenID RelyingParty support module

=head1 SYNOPSIS

    my $openid = OpenID::Lite::RelyingParty->new();

    sub login {

        my $self = shift;

        my $user_suplied_identifier = $self->req->param('openid_identifier');
        return unless $self->validate( $user_suplied_identifier );

        my $checkid_request = $openid->begin( $user_suplied_identifier )
            or $self->show_error( $openid->errstr );

        my $sreg = OpenID::Lite::Extension::SREG::Request->new;
        $sreg->request_fields(qw(nickname));

        $checkid_request->add_extension($sreg);

        my $redirect_url = $checkid_request->redirect_url(
            return_to => q{http://example.com/return_to},
            realm     => q{http://example.com/},
        );

        return $self->redirect_to( $redirect_url );
    }

    sub return_to {
        my $self = shift;
        my $openid = OpenID::Lite::RelyingParty->new;

        my $res = $openid->complete( $self->request, q{http://myapp/return_to} );

        if ( $res->is_success ) {

            # openid login successfully completed.
            # you should save the verified identifier.

            my $display_identifier = $res->display_identifier;
            my $identity_url       = $res->identity_url;

        } elsif ( $res->is_canceled ) {

            # user canceled openid-login.
            #
            # redirect back to top-page or login-page.
            return $your_app->redirect('http://yourapp.com/');

        } elsif ( $res->is_setup_needed ) {

            # you requested as immediate-mode.
            # but OP requires setup.

            # so, then redirect to the indicated url
            return $your_app->redirect( $res->url );

            # if you accept OP with white-list,
            # You can know whether the OP accepts immedate mode or not.
            # So, it's better to change not to use immediate-mode.

        } elsif ( $res->is_not_openid ) {

            return $your_app->error('request is not for openid.');

        } elsif ( $res->is_invalid ) {

            # failed to verify returned assertion
            $your_app->log( $res->message );
            $your_app->error('Failed to verify assertion.');

        } elsif ( $res->is_error ) {

            # error response.
            $your_app->log( $res->message );
            $your_app->log( $res->contact );
            $your_app->log( $res->referrence );

            $your_app->error('Got error response from OP');

        }

    }

=head1 DESCRIPTION

This module allows you to make OpenID RelyingParty easily.
This supports OpenID 2.0.
Most of these interface is borrowd from ruby-openid which is provided by OpenID Enabled.

You only have to execute 'begin' and 'complete'.
These methods automatically and properly execute each OpenID communication.

But if you want to customize behavior in detail,
You alco can use rower API of this module, for example,
'discover', 'associate', 'idres', and so on.

'Lite' means nothing. It's to escape namespace confliction.

=head1 PREPARE

You should start with preparing OpenID::Lite::RelyingParty object with defualt set.

    my $openid_rp = OpenID::Lite::RelyingParty->new();

Or set options.

    use OpenID::Lite::Constants::AssocType qw(HMAC_SHA256);
    use OpenID::Lite::Constants::SessionType qw(DH_SHA256);
    my $openid_rp = OpenID::Lite::RelyingParty->new(
        assoc_type   => HMAC_SHA256,
        session_type => DH_SHA256,
        session      => $myapp->session, # HTTP::Session object or other object which has same interface.
        agent        => $agent,
        store        => OpenID::Lite::RelyingParty::Store::Cache->new,
    );

=head2 new

=over4

=item assoc_type

HMAC_SHA1 is set by default.
L<OpenID::Lite::Constants::AssocType>

=item session_type

NO_ENCRYPTION is set by default.
L<OpenID::Lite::Constants::SessionType>

=item agent

If you omit, L<LWP::UserAgent> is set by default.

To keep your application secure, you'd better set agent with more-secure one.
like L<LWPx::ParanoidAgent> or L<OpenID::Lite::Agent::Paranoid>.

L<OpenID::Lite::Agent::Dump> dump the request and response object for debug.

=item session

To reduce the cost on 'idres', you can set session object.
This object must behaves as same as L<HTTP:Session> object.
(Just requires only 'get' and 'set' methods.)

If session is set and discovery is executed by claimed-id,
On 'idres' process, it need'nt execute re-discovery to verify
returned information.

See Also
L<HTTP::Session>

=item store

This if for saving associations which is established between RP and OP.
If this is undef, OpenID process is carried out as 'stateless mode'.
In stateless case, check_authentication http request is required
to verify signature included in checkid-response.

You had better to set this to reduce networking cost.
If your RP site allows OP with white-list (maybe this is a standard way now),
Not so much associations are build. So Hash object on memory is enough to store them.
L<OpenID::Lite::RelyingParty::Store::OnMemory> fits for this case.

But your site accepts all the OpenID Providers,
More assocations will be established with them.
Then you may need another solution.

If you omit, L<OpenID::Lite::RelyingParty::Store::OnMemory> is set by default.
In future OpenID::Lite::RelyingParty::Store::Cache will be pushed into this package.

See Also
L<OpenID::Lite::RelyingParty::Store::OnMemory>

=back

=head1 BEGIN

You should

1. normalize user suplied identifier
2. execute discovery with identifier ( if arleady you obtained OP's information, you can omit this phase )
3. established association with OP ( if stateless mode, this phase is omitted )
4. make check-id request
5. redirect user to OP's endpoint as checkid-request.

There are methods corresponding to each phase.
You can use them or simple 'begin' methods that execute
most of these process automatically.

simple API example

    sub login {
        my $your_app = shift;
        my $identifier = $your_app->req->param('openid_identifier');
        # $your_app->validate_identifier( $identifier );

        my $checkid_request = $openid_rp->begin( $identifier )
            or $your_app->show_error( $your_app->openid->errstr );

        my $endpoint_url = $checkid_request->redirect_url(
            return_to => q{http://myapp.com/return_to},
            realm     => q{http://myapp.com/},
        );

        return $your_app->redirect( $endpoint_url );
    }

simple API and limiting OP and reducing discovery-cost.

    use OpenID::Lite::Constants::Namespace qw(SERVER_2_0);

    sub login {
        my $your_app = shift;

        my $service = OpenID::Lite::RelyingParty::Discover::Service->new;
        $service->add_type( SERVER_2_0 );
        $service->add_uri( q{http://example.com/op/endpoint} );

        my $checkid_request = $openid_rp->begin_without_discovery( $service );

        my $endpoint_url = $checkid_request->redirect_url(
            return_to => q{http://myapp.com/return_to},
            realm     => q{http://myapp.com/},
        );

        return $your_app->redirect( $endpoint_url );
    }

raw API example

    sub login {
        my $your_app = shift;
        my $identifier = $your_app->req->param('openid_identifier');
        # $your_app->validate_identifier( $identifier );

        $identifier = $openid_rp->normalize_identifier( $identifier )
            or return $your_app->error( $openid_rp->errstr );

        my $services = $openid_rp->discover( $identifier )
            or return $your_app->error( $openid_rp->errstr );

        unless ( @$services > 0 ) {
            return $your_app->error('No proper OpenID Provider found.');
        }

        my $service = $services->[0];

        my $association = $openid_rp->associate( $services->[0] )
            or return $your_app->error( $openid_rp->errstr );

        $your_app->save_association( $service, $association );
        $your_app->session->set( 'openid.last_requested_endpoint', $service );

        my $checkid_request = OpenID::Lite::RelyingParty::CheckID::Request->new(
            service     => $service,
            association => $association,
        );

        my $endpoint_url = $checkid_request->redirect_url(
            return_to => q{http://myapp.com/return_to},
            realm     => q{http://myapp.com/},
        );

        return $your_app->redirect( $endpoint_url );
    }

=head2 normalize_identifier($identifier)

Normalize user suplied identifier,
and return OpenID::Lite::Identifier object.

    my $normalized_identifier = $openid_rp->normalized_identifier($user_suplied_identifier)
        or die $openid_rp->errstr;

=head2 discover($normalized_identifier)

Do discovery and return found service informations(Array of OpenID::Lite::RelyingParty::Discover::Service)

    $services = $openid_rp->discover( $normalized_identifier )
        or die $openid_rp->errstr;

=head2 associate($service)

Establish association with OP.
Returns <OpenID::Lite::Association> object.

    my $association = $openid_rp->associate( $service )
        or die $openid_rp->errstr;

=head2 begin($user_suplied_identifier)

Return <OpenID::Lite::relyingParty::CheckID::Request> object.

    my $checkid_req = $openid_rp->begin( $identifier )
        or die $openid_rp->errstr;

=head2 begin_without_discovery($service)

Return <OpenID::Lite::relyingParty::CheckID::Request> object.

    my $checkid_req = $openid_rp->begin_without_discovery( $service )
        or die $openid_rp->errstr;

=head1 APPEND EXTENSION

You can add extension request onto checkid request.

    my $chekid_req = $openid_rp->begin(...);

    my $sreg_req = OpenID::Lite::Extension::SREG::Request->new;
    $sreg_req->request_field('nickname');
    $sreg_req->request_field('fullname');
    $checkid_req->add_extension( $sreg_req );

    my $ui_req = OpenID::Lite::Extension::UI::Request->new;
    $ui_req->mode('popup');
    $checkid_req->add_extension( $ui_req );

    my $url = $checkid_req->redirect_url(
        ...
    );

=head1 COMPLETE

When OP redirect back user to the return_to url you
defined on checkid-request, you should execute 'idres'.
You can choose row API and simple wrapper here too.


row API example

    sub complete {
        my $your_app = shift;

        my $params = OpenID::Lite::Message->from_request( $your_app->request );
        my $service = $your_app->session->get('openid.last_requested_endpoint');
        my $association = $your_app->load_association_for( $service );

        my $res = $openid_rp->idres(
            service     => $service,
            association => $association,
            params      => $params,
            current_url => q{http://yourapp.com/return_to},
        );

        if ( $res->is_success ) {

            # openid login successfully completed.
            # you should save the verified identifier.

            my $display_identifier = $res->display_identifier;
            my $identity_url       = $res->identity_url;

        } elsif ( $res->is_canceled ) {

            # user canceled openid-login.
            #
            # redirect back to top-page or login-page.
            return $your_app->redirect('http://yourapp.com/');

        } elsif ( $res->is_setup_needed ) {

            # you requested as immediate-mode.
            # but OP requires setup.

            # so, then redirect to the indicated url
            return $your_app->redirect( $res->url );

            # if you accept OP with white-list,
            # You can know whether the OP accepts immedate mode or not.
            # So, it's better to change not to use immediate-mode.

        } elsif ( $res->is_not_openid ) {

            return $your_app->error('request is not for openid.');

        } elsif ( $res->is_invalid ) {

            # failed to verify returned assertion
            $your_app->log( $res->message );
            $your_app->error('Failed to verify assertion.');

        } elsif ( $res->is_error ) {

            # error response.
            $your_app->log( $res->message );
            $your_app->log( $res->contact );
            $your_app->log( $res->referrence );

            $your_app->error('Got error response from OP');

        }

    }

simple API example

    sub complete {
        my $your_app = shift;

        my $current_url = q{http://yourapp.com/return_to};
        my $res = $openid_rp->complete( $your_app->request, $current_url );

        # same as row API example above
        if ( $res->is_success ) {
            ...
        } elsif ( $res->is_canceled ) {
            ...
        } elsif ( $res->is_setup_needed ) {
            ...
        } elsif ( $res->is_not_openid ) {
            ...
        } elsif ( $res->is_invalid ) {
            ...
        } elsif ( $res->is_error ) {
            ...
        }

    }

=head2 idres(%args)

Returns OpenID::Lite::RelyingParty::CheckID::Result object.

=over 4

=item params(required)

OpenID::Lite::Message object.
You should encode your request to OpenID::Lite::Message.

=item current_url(required)

URL string that represents the endpoint you indicate
as return_to on checkid-request.

=item services(optional)

=item association(optional)

=back

=head2 complete($request, $current_url)

Returns OpenID::Lite::RelyingParty::CheckID::Result object.

=head1 EXTRACT EXTENSION RESPONSE

In successfull response,
You can extract extension data you requested.

    } elsif ( $res->is_success ) {

        my $sreg_res = OpenID::Lite::Extension::SREG::Response->from_success_response($res);
        my $data = $sreg_res->data;
        my $nickname = $data->{nickname}||'';
        my $fullname = $data->{fullname}||'';
        ...
    }

=head1 SEE ALSO

http://openid.net/specs/openid-authentication-2_0.html
http://openidenabled.com/

=head2 TODO

=over 4

=item Improve an interoperability with majour services.

=back

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
