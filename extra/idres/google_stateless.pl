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

use Perl6::Say;
use MIME::Base64 qw(decode_base64 encode_base64);
use Data::Dump qw(dump);

use Test::More qw(no_plan);

sub build_service {
    my $service = OpenID::Lite::RelyingParty::Discover::Service->new(
        types => [
            "http://specs.openid.net/auth/2.0/server",
            "http://openid.net/srv/ax/1.0",
        ],
        uris => ["https://www.google.com/accounts/o8/ud?source=gmail"],
    );
    return $service;
}

sub build_message {
    my $response
        = q{openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=id_res&openid.op_endpoint=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fud&openid.response_nonce=2009-06-05T08%3A31%3A36ZoTIOzPrR-N6dCQ&openid.return_to=http%3A%2F%2Fexample.com%2Freturn_to&openid.assoc_handle=AOQobUdtzE2Lnh2RpupvMlH0TO49qba-p1RZl8O8nrhvwNR9pbitrbrL&openid.signed=op_endpoint%2Cclaimed_id%2Cidentity%2Creturn_to%2Cresponse_nonce%2Cassoc_handle&openid.sig=PDa8JvZ%2FSsPEgbyUPlbvarfQFlU%3D&openid.identity=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fid%3Fid%3DAItOawnPdjM5hX0L4vR06KyKM59k8GDhXMGJKTQ&openid.claimed_id=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fid%3Fid%3DAItOawnPdjM5hX0L4vR06KyKM59k8GDhXMGJKTQ};

    my $message = OpenID::Lite::Message->new;
    for my $pair ( split /&/, $response ) {
        my ( $k, $v ) = split /=/, $pair;
        $k =~ s/^openid\.//;
        $v = URI::Escape::uri_unescape($v);
        $message->set( $k, $v );
    }
    return $message;
}

sub build_association {
    my $secret = q{MobchdRPuirQdGQ7pIstU82tOfs=};
    $secret = decode_base64($secret);
    my $assoc = OpenID::Lite::Association->new(
        handle => q{AOQobUcFJ-pwwZF42uhiKYYjH0fu4WZWE9xX3MrcftsZPGq2ftgJV6bk},
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
my $message = &build_message();
my $assoc   = &build_association();
my $store   = &build_store();

#$store->store_association( $service->url, $assoc );
use OpenID::Lite::Agent::Dump;
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
    service     => $service
);

ok($res->is_success);

say dump($res);

