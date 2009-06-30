package OpenID::Lite::Provider;

use Any::Moose;
use OpenID::Lite::Message;
use OpenID::Lite::Realm;
use OpenID::Lite::Provider::Discover;
use OpenID::Lite::Provider::Response;
use OpenID::Lite::Provider::AssociationBuilder;
use OpenID::Lite::Provider::Handler::Association;
use OpenID::Lite::Provider::Handler::CheckAuth;
use OpenID::Lite::Provider::Handler::CheckID;
use OpenID::Lite::Constants::ModeType qw(:all);
use OpenID::Lite::Constants::Namespace qw(:all);
use OpenID::Lite::Constants::ProviderResponseType qw(:all);

with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';

has 'secret_lifetime' => (
    is      => 'rw',
    isa     => 'Int',
    default => 14 * 24 * 60 * 60,
);

has 'server_secret' => (
    is      => 'ro',
    isa     => 'Str',
    default => q{secret},
);

#has 'secret_gen_interval' => (
#    is      => 'rw',
#    isa     => 'Int',
#    default => 14 * 24 * 60 * 60,
#);
#
#has 'get_server_secret' => (
#    is      => 'ro',
#    isa     => 'CodeRef',
#    default => sub {
#        sub { return ''; }
#    },
#);
#
has 'setup_url' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'endpoint_url' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
);

has 'get_user' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return; }
    },
);

has 'get_identity' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return; }
    },
);

has 'is_identity' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return; }
    },
);

has 'is_trusted' => (
    is      => 'ro',
    isa     => 'CodeRef',
    default => sub {
        sub { return; }
    },
);

has '_discoverer' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::Provider::Discover',
    lazy_build => 1,
);

has '_assoc_builder' => (
    is         => 'ro',
    isa        => 'OpenID::Lite::Provider::AssociationBuilder',
    lazy_build => 1,
);

has '_handlers' => (
    is         => 'ro',
    isa        => 'HashRef',
    lazy_build => 1,
);

sub handle_request {
    my ( $self, $request ) = @_;
    my $params = OpenID::Lite::Message->from_request($request);
    my $mode   = $params->get('mode');
    return $self->ERROR(q{Missing parameter, "mode"}) unless $mode;
    my $handler = $self->_get_handler_for($mode);
    return $self->ERROR( sprintf q{Invalid paramter, "mode", "%s"}, $mode )
        unless $handler;
    my $result = $handler->handle_request($params)
        or return $self->ERROR( $handler->errstr );
    return $result;
}

sub _get_handler_for {
    my ( $self, $mode ) = @_;
    if ( $mode eq ASSOCIATION ) {
        return $self->_handlers->{associate};
    }
    elsif ( $mode eq CHECK_AUTHENTICATION ) {
        return $self->_handlers->{checkauth};
    }
    elsif ($mode eq CHECKID_SETUP
        || $mode eq CHECKID_IMMEDIATE )
    {
        return $self->_handlers->{checkid};
    }
    return;
}

sub _build__handlers {
    my $self     = shift;
    my $handlers = {};
    $handlers->{associate}
        = OpenID::Lite::Provider::Handler::Association->new(
        assoc_builder => $self->_assoc_builder, );

    $handlers->{checkauth} = OpenID::Lite::Provider::Handler::CheckAuth->new(
        assoc_builder => $self->_assoc_builder, );

    $handlers->{checkid} = OpenID::Lite::Provider::Handler::CheckID->new(
        assoc_builder => $self->_assoc_builder,
        setup_url     => $self->setup_url,
        endpoint_url  => $self->endpoint_url,
        get_user      => $self->get_user,
        get_identity  => $self->get_identity,
        is_identity   => $self->is_identity,
        is_trusted    => $self->is_trusted,
    );
    return $handlers;
}

sub _build__assoc_builder {
    my $self          = shift;
    my $assoc_builder = OpenID::Lite::Provider::AssociationBuilder->new(
        server_secret       => $self->server_secret,
        secret_lifetime     => $self->secret_lifetime,
#       secret_gen_interval => $self->secret_gen_interval,
#       get_server_secret   => $self->get_server_secret,
    );
    return $assoc_builder;
}

# my $req = $op->make_op_initiated_assertion( $rp_realm, $user_identifier )
#   or $your_app->error( $op->errstr );
# $your_app->redirect( $req->make_singed_url() );

sub make_op_initiated_assertion {
    my ( $self, $rp_realm, $identifier ) = @_;
    my $urls = $self->discover_rp($rp_realm)
        or return;
    return $self->ERROR( sprintf q{url not found for realm, "%s"}, $rp_realm )
        unless @$urls > 0;
    return $self->make_op_initiated_assertion_without_discovery( $rp_realm,
        $urls->[0], $identifier );
}

sub make_op_initiated_assertion_without_discovery {
    my ( $self, $rp_realm, $url, $identifier ) = @_;

    my $message = OpenID::Lite::Message->new;
    $message->set( ns         => SIGNON_2_0 );
    $message->set( realm      => $rp_realm );
    $message->set( claimed_id => $identifier );
    $message->set( identity   => $identifier );
    $message->set( return_to  => $url );

    return OpenID::Lite::Provider::Response->new(
        type          => POSITIVE_ASSERTION,
        req_params    => $message,
        res_params    => $message,
        assoc_builder => $self->_assoc_builder,
        endpoint_url  => $self->endpoint_url,
    );
}

sub discover_rp {
    my ( $self, $rp_realm ) = @_;
    unless ( ref($rp_realm) eq 'OpenID::Lite::Realm' ) {
        $rp_realm = OpenID::Lite::Realm->parse($rp_realm)
            or
            return $self->ERROR( sprintf q{Invalid realm "%s"}, $rp_realm );
    }
    my $return_to_urls
        = $self->_discoverer->discover( $rp_realm->build_discovery_url )
        or return $self->ERROR( $self->_discover->errstr );
    return $return_to_urls;
}

sub _build__discoverer {
    my $self = shift;
    return OpenID::Lite::Provider::Discover->new( agent => $self->agent );
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

=head1 NAME

OpenID::Lite::Provider - OpenID Provider support module

=head1 SYNOPSIS

OpenID Controller

    package YourApp::OpenIDController;

    my $op = OpenID::Lite::Provider->new(
        endpoint_url  => q{http://yourapp.com/openid},
        setup_url     => q{http://yourapp.com/setup},
        server_secret => q{SECRETKEY},
    );

    # server endpoint
    sub openid {

        my $your_app = shift;

        my $result = $op->handle_request( $your_app->request );

        if ( !$result ) {

            # error occured
            # invalid as openid-request.
            $your_app->view->content_type('text/plain');
            $your_app->view->content($op->errstr);
            return;

        } elsif ( $result->is_for_setup ) {

            # save the parameters into session
            # this is just an example, you can take other ways.
            # for example, use query-string parameter.
            $your_app->session->set( 'openid.checkid' => $result );

            # required setup and
            # show decision page

            # Case 1. redirect to action that is for setup
            $your_app->redirect_to( $your_app->uri_to( action => 'setup' ) );
            return;

            # Case 2. or directly show setup page.
            $your_app->view->render('decision_page', {
                realm => $result->get_realm(),
            } );

        } elsif ( $result->requires_setup ) {

            # RP requested as immediate-mode, but your app (provider)
            # doesn't accept immediate mode.
            return $your_app->redirect_to( $result->make_setup_url() );

        } elsif ( $result->is_positive_assertion ) {

            # successfully done as immediate-mode.

            # execute extension processes here if you need.
            my $sreg_req = OpenID::Lite::Extension::SREG::Request->from_provider_response($result);
            my $user_data = $self->session->get('user');
            my $sreg_data = {
                nickname => $user_data->nickname,
                fullname => $user_data->fullname,
                email    => $user_data->email,
            };
            my $sreg_res = OpenID::Lite::Extension::SREG::Response->extract_response($sreg_req, $sreg_data);
            $result->add_extension( $sreg_res );

            # redirect back to RP with successful signed params.
            return $self->redirect_to( $result->make_signed_url() );

        } elsif ( $result->is_for_direct_communication ) {

            # direct communication response
            # This case is for establishing association and checking auth.
            $self->view->content( $result->content );
            return;

        } elsif ( $result->is_checkid_error ) {

            return $self->redirect_to( $self->make_error_url() );

        }
    }

    # action that shows decision page.
    sub setup {
        my $self = shift;
        my $checkid_result = $self->session->get('openid.checkid');
    }

    # if user canceled to approve RP request.
    sub user_cancel {
        my $self = shift;
        my $checkid_result = $self->session->get('openid.checkid');
        return $self->redirect_to( $checkid_result->make_cancel_url() );
    }

    # if user approved RP request.
    sub user_approved {
        my $self = shift;

        my $checkid_result = $self->session->get('openid.checkid')
            or return $self->show_error('Invalid openid-session');

        # RETURN POSITIVE ASSERTION
        # redirect to RP as positive-assertion

        # execute extension processes here if you need.
        my $sreg_req = OpenID::Lite::Extension::SREG::Request->from_provider_response($checkid_result);
        my $user_data = $self->session->get('user');
        my $sreg_data = {
            nickname => $user_data->nickname,
            fullname => $user_data->fullname,
            email    => $user_data->email,
        };
        my $sreg_res = OpenID::Lite::Extension::SREG::Response->extract_response($sreg_req, $sreg_data);
        $checkid_result->add_extension( $sreg_res );
        return $self->redirect_to( $checkid_result->make_signed_url() );
    }

    1;

Application Root

    package YourApp::RootController;

    sub root {
        my $self = shift;
        if ( $self->req->header('Accept') =~ m!application/xrds+xml!i ) {
            print_xrds();
            return;
        }
    }
    1;

User Page

    package YourApp::UserController;

    sub user {
        my ( $self, $user_id ) = @_;
        if ( $self->req->header('Accept') =~ m!application/xrds+xml!i ) {
            print_claimed_id_xrds($user_id);
            return;
        }
    }

    1;


=head1 DESCRIPTION

This moduel allows you to mae OpenID Provider easily.
This supports OpenID 2.0.

'Lite' means nothing. It's to escape namespace confliction.

=head1 SETUP

    my $op = OpenID::Lite::Provider->new(
        endpoint_url => q{http://yourapp.com/openid},
        setup_url    => q{http://yourapp.com/setup},
    );

=head2 new

parameters

=over 4

=item setup_url

The OpenID setup url.

=item endpoint_url

The OpenID endpoint url.

=item server_secret

Secret string to generate association.

=item secret_lifetime

Lifetime seconds for each association.

=item agent

Used for RP discovery.

See L<LWP::UserAgent>, L<LWPx::ParanoidAgent>
L<OpenID::Lite::Agent::Dump>, L<OpenID::Lite::Agent::Paranoid>

=back

Callback functions
You can set callbacks, then they will be able to automatically
controll to judge approve request from RP or not.
If you want to manually handle request,
see 'REQUEST HANDLING' section.

=over 4

=item get_user

Callback function to get current user object.
Other callback functions uses the returned user object.

    my $your_app = ...;
    get_user => sub {
        return $your_app->session->get('user');
    }

=item get_identity

Callback function to get user identity.
If your app provieds users multiple identifier for each realm,
use the second arg.

    get_identity => sub {
        my ( $user, $realm ) = @_;

        # if your app provides users with only single identifier
        return $user->get_identity();

        # if your app provides users with diffirent identifier for each realm.
        return $user->get_identity_for($realm);
    }

=item is_identity

Callback function that checks the passed identity is
for indicated user's one or not.
If your app provieds users multiple identifier for each realm,
use the third arg.

    is_identity => sub {
        my ( $user, $identity, $realm ) = @_;
        return ( $user->get_identity_for($realm) eq $identity ) ? 1 : 0;
    }

=item is_trusted

Callback function that checks that if the current user trusts
requesting RP or not.

    is_trusted => sub {
        my ( $user, $realm ) = @_;
        return $user->trust( $realm ) ? 1 : 0;
    }

=back

=head1 REQUEST HANDLING

execute handle_reuqest method, and
switch process properly for each result type.

    my $result = $op->handle_request( $your_app->request );
    if ( !$result ) {
        # error
    } elsif ( ... ) {

    } elsif ( ... ) {

    } elsif ( ... ) {

    }

=head2 NOT FOUND RESULT

If $op->handle_request returns nothing.
You can pick the error string from $op->errstr method.

    if ( !$result ) {
        $your_app->log( $op->errstr );
        $your_app->show_error( q{ Invalid openid request.} );
    }

=head2 POSITIVE ASSERTION

When OP accept the case like that, user had already approved the requesting RP,
returns positive assertion directly without displaying dicision page.
To accomplish this, you have to set callback functions(get_user, get_identity, and so on)
when calling 'new' method.



    } elsif ( $result->is_positive_assertion ) {

        $your_app->redirect( $result->make_signed_url() );
    } ...

And if you need support extension.
Do their process here, or SETUP phase discribed bellow.

    } elsif ( $result->is_positive_assertion ) {

        my $sreg_req = OpenID::Lite::Extension::SREG::Request->from_provider_response( $result );
        my $user_data = $self->session->get('user');
        my $sreg_data = {
            nickname => $user_data->nickname,
            fullname => $user_data->fullname,
            email    => $user_data->email,
        };
        my $sreg_res = OpenID::Lite::Extension::SREG::Response->extract_response($sreg_req, $sreg_data);
        $result->add_extension( $sreg_res );

        $your_app->redirect( $result->make_signed_url() );
    } ...


=head2 SETUP

When RP requests checkid not-immediate request,
and no error found.( for the case if error found, see CHECKID ERROR section ).

Normally, you can choose two ways here,
Show dicision page directly, or redirect user to setup-url.

And to show some information to users.
You can pick them from result object.
see get_relam, get_claimed_id, get_identity methods bellow.

It is better to save result information into session
until user will be back with setup completion action or canceling action.
In those actions, result object will be required.

And you can set identifier for user here with
'set_identity' method of result object.


1. Redirecting case.

    } elsif ( $result->is_for_setup ) {

        $your_app->session->save( 'openid' => $result );

        $your_app->redirect( $result->make_setup_url() );

        # or manually make url by yourself.
        #$your_app->redirect( $your_app->uri_for(
        #    action => 'setup', 
        #) );
    }


2. Show dicision page case.

    } elsif ( $result->is_for_setup ) {

        my $realm = $result->get_realm();

        # if you set get_identity callback to Provider object,
        # you may get identity by this method.
        my $identity   = $result->get_identity();

        # or set manually here.
        # my $identity = $your_app->build_user_identity(
        # $your_app->session->get('user')->id );
        # $result->set_identity( $identity );

        $your_app->session->save( 'openid' => $result );

        $your_app->show_dicition_page(
            realm      => $realm,
            identity   => $identity,
        );
    } ...

And as described on POSITIVE ASSERTION phase,
You can extract information for extension.

    } elsif ( $result->is_for_setup ) {

        my $realm = $result->get_realm();

        # if you set get_identity callback to Provider object,
        # you may get identity by this method.
        my $identity   = $result->get_identity();

        # or set manually here.
        # my $identity = $your_app->build_user_identity(
        # $your_app->session->get('user')->id );
        # $result->set_identity( $identity );

        $your_app->session->save( 'openid' => $result );

        my $sreg_req = OpenID::Lite::Extension::SREG::Request->from_provider_response( $result );

        my $fields  = $sreg_req->all_requested_fields();
        my $message = '';
        if ( @$fields > 0 ) {
            $message = sprintf(q{the RP requests your fields, "%s"},
                join(', ', @$fields) );
        }

        my $template = 'decision_page.tt';

        my $ui_req = OpenID::Lite::Extension::UI::Request->from_provider_response( $result );
        if ( $ui_req->mode eq 'popup' ) {
            $template = 'decision_page_for_popup.tt';
        }

        $your_app->show_dicition_page(
            template   => $template,
            realm      => $realm,
            identity   => $identity,
            message    => $message,
        );
    } ...

=head2 REQUIRES SETUP

RP send checkid-request but OP doesn't accept immedate mode.
OP should let RP know setup-url.

    } elsif ( $result->requires_setup ) {
        $your_app->redirect( $result->make_setup_url() );
    } ...

=head2 DIRECT COMMUNICATION

For establishing association or CheckAuth request.
Directly print key-value form encoded content.

    } elsif ( $result->is_direct_communication ) {
        $your_app->view->content( $result->content );
    } ...

=head2 CHECKID ERROR

If any error occured while processing checkid-request,
You should redirect user back to RP with openid-error parameters.

    } elsif ( $result->is_checkid_error ) {
        $your_app->redirect( $result->make_error_url() );
    } ...

=head1 OP INITIATE

execute discovery and find return_to url by realm.
But it works only when RP implements XRDS publishing correctly for realm.

    my $assertion = $op->make_op_initiated_assertion(
        $rp_realm,
        $current_user_identifier,
    ) or $your_app->error( $op->errstr );

Or if you already know the return_to url corresponding to the realm.
You can make assertion without discovery.

    my $assertion = $op->make_op_initiated_assertion_without_discovery(
        $rp_realm,
        $rp_return_to,
        $current_user_identifier,
    ) or $your_app->error( $op->errstr );

If you need, add extension here

    my $ext_res = OpenID::Lite::Extension::Something::Response->new;
    $ext_res->add_some_param( foo => 'bar' );
    $assertion->add_extension( $ext_res );

And finally, build signed url to redirect with it.

    $your_app->redirect( $assertion->make_signed_url() );

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
