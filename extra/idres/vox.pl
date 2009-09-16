#!/usr/bin/perl

use strict;
use warnings;

use lib '../../lib';

use OpenID::Lite::Message;
use OpenID::Lite::Association;
use OpenID::Lite::SignatureMethods;
use OpenID::Lite::RelyingParty::Discover::Service;
use OpenID::Lite::RelyingParty::IDResHandler;
use OpenID::Lite::RelyingParty::IDResHandler::Verifier;
use OpenID::Lite::RelyingParty::Store::OnMemory;
use OpenID::Lite::Agent::Dump;

use Perl6::Say;
use MIME::Base64 qw(decode_base64 encode_base64);
use Data::Dump qw(dump);

use Test::More qw(no_plan);

sub build_service {
    my $identifier = q{lyokato.vox.com};
    my $id = OpenID::Lite::Identifier->normalize($identifier);
    my $disco = OpenID::Lite::RelyingParty::Discover->new(
#agent=>OpenID::Lite::Agent::Dump->new
    );
    my $servers = $disco->discover($id)
        or die $disco->errstr;

    my $service = $servers->[0];

    return $service;
}

sub build_stateful_message {
    my $response = q{rp_nonce=2009-09-16T05%3A45%3A31ZB6ecgA&openid1_claimed_id=http%3A%2F%2Flyokato.vox.com%2F&openid.mode=id_res&openid.identity=http://lyokato.vox.com/&openid.return_to=http://example.com/return_to%3Frp_nonce%3D2009-09-16T05%253A45%253A31ZB6ecgA%26openid1_claimed_id%3Dhttp%253A%252F%252Flyokato.vox.com%252F&openid.issued=2009-09-16T05:45:42Z&openid.valid_to=2009-09-16T06:45:42Z&openid.assoc_handle=1253079931:NtrpKkVQ2BNzWzIDzSZ8:dcdb04cee3&openid.signed=mode,identity,return_to,issued,valid_to&openid.sig=i5Nmyy8AaLTR9X/OSFSc0mraX9U%3D};

    use CGI;
    my $query = CGI->new($response);
    my $message = OpenID::Lite::Message->from_request($query);
    use Data::Dump qw(dump);
    warn dump($message);
    warn dump( $message->get_extra('openid1_claimed_id') );
=pod
    for my $pair ( split /&/, $response ) {
        my ( $k, $v ) = split /=/, $pair;
        $k =~ s/^openid\.//;
        $v = URI::Escape::uri_unescape($v);
        $message->set( $k, $v );
    }
=cut
    return $message;
}

=pod
ASSOC_TYPE:   HMAC-SHA1
ASSOC_HANDLE: 1253079931:NtrpKkVQ2BNzWzIDzSZ8:dcdb04cee3
EXPIRATION:   1254286800
SECRET:       bVXJZnehnJqSpmq6R/Oyyhdp51w=
=cut
sub build_association {
my $secret = q{bVXJZnehnJqSpmq6R/Oyyhdp51w=};
    $secret = decode_base64($secret);
    my $assoc = OpenID::Lite::Association->new(
handle => q{1253079931:NtrpKkVQ2BNzWzIDzSZ8:dcdb04cee3},
        secret => $secret,
        type   => q{HMAC-SHA1},
        issued => time(),
        expires_in => time() + 86400,
    );
    return $assoc;
}

sub build_store {
    my $store = OpenID::Lite::RelyingParty::Store::OnMemory->new;
    return $store;
}

my $bad_current_url = q{http://example.org/return_to};
my $current_url = q{http://example.com/return_to};
my $service = &build_service();
my $message = &build_stateful_message();
my $assoc   = &build_association();
my $store   = &build_store();

$store->store_association( $service->url, $assoc );
my $idres = OpenID::Lite::RelyingParty::IDResHandler->new( store => $store, agent => OpenID::Lite::Agent::Dump->new );

my $bad_url_res = $idres->idres(
    current_url => $bad_current_url,
    params      => $message,
    service     => $service
);

is($bad_url_res->type, q{invalid});

my $res = $idres->idres(
    current_url => $current_url,
    params      => $message,
#    service     => $service
);

ok($res->is_success);

say dump($res);
say $res->display_identifier;
say $res->identity_url;



