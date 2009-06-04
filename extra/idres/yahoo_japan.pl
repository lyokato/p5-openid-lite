#!/usr/bin/perl

use strict;
use warnings;

use lib '../../lib';

use OpenID::Lite::Message;
use OpenID::Lite::SignatureMethods;
use MIME::Base64 qw(decode_base64 encode_base64);
use Perl6::Say;
use Digest::SHA1 qw(sha1);


my $response = q{openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=id_res&openid.return_to=http%3A%2F%2Fexample.org%2Freturn_to&openid.claimed_id=https%3A%2F%2Fme.yahoo.co.jp%2Fa%2FyE.9G9xtVfQgeBQvoCe8AyFG9sc-%23ba6e4&openid.identity=https%3A%2F%2Fme.yahoo.co.jp%2Fa%2FyE.9G9xtVfQgeBQvoCe8AyFG9sc-&openid.assoc_handle=WNDaDJ9DEasVaGkwYQ2T8qbLTG16aa0gEtZU_JRFYRaL5SWurLFoDkglxr5ZWdVMngGxHHNuERIe9BNi08zTo4iSbzW2pbmE.swubIL141aExp19kPcQyxGpBidX_DTqPA--&openid.realm=http%3A%2F%2Fexample.org&openid.response_nonce=2009-06-04T15%3A43%3A02ZgphPTAo0qa4pi3NwKbA.WlWQtEyLLoV4CA--&openid.signed=assoc_handle%2Cclaimed_id%2Cidentity%2Cmode%2Cns%2Cns.pape%2Cop_endpoint%2Cpape.auth_policies%2Cpape.nist_auth_level%2Cresponse_nonce%2Creturn_to%2Csigned&openid.op_endpoint=https%3A%2F%2Fopen.login.yahooapis.jp%2Fopenid%2Fop%2Fauth&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0&openid.pape.auth_policies=none&openid.pape.nist_auth_level=0&openid.sig=wU1uPT0sOSQSOPpHrfO4c1t8eMM%3D};

my $message = OpenID::Lite::Message->new;
for my $pair ( split /&/, $response) {
    my ($k, $v) = split /=/, $pair;
    $k =~ s/^openid\.//;
    $v = URI::Escape::uri_unescape($v);
    warn '===================';
    warn $k;
    warn $v;
    $message->set($k, $v);
}


my $secret = q{uqxdDBnyu99AM1YVLvodAjgJuoE=};
$secret = decode_base64($secret);
say $secret;
say length($secret);

my $method = OpenID::Lite::SignatureMethods->select_method('HMAC-SHA1');
say $method->sign( $secret, $message );
say $message->get('sig');

say $method->verify( $secret, $message );

