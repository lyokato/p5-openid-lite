#!/usr/bin/perl

use strict;
use warnings;

use lib '../../lib';

use OpenID::Lite::Message;
use OpenID::Lite::SignatureMethods;
use MIME::Base64 qw(decode_base64 encode_base64);
use Perl6::Say;
use Digest::SHA1 qw(sha1);


my $response = q{openid.ns=http://specs.openid.net/auth/2.0&openid.mode=id_res&openid.return_to=http://lyokato.com/return_to&openid.claimed_id=https://me.yahoo.co.jp/a/yE.9G9xtVfQgeBQvoCe8AyFG9sc-%23ba6e4&openid.identity=https://me.yahoo.co.jp/a/yE.9G9xtVfQgeBQvoCe8AyFG9sc-&openid.assoc_handle=QUmHlxVQQOg79zzdI8rpbEzjuIiNExHiBBh8gaBNcLLiDo21JqaA9pS5vYR.RMKlCqUuWLfI5NryCOJpxkQ6sl0loFU.tLjtpGG6G.x5vH0JT5ttrm8G80.ogieACch6cw--&openid.realm=http://lyokato.com&openid.response_nonce=2011-02-23T07:42:38ZmhXJifN8ABGzs0B5la44aTn25XDavEiVXw--&openid.signed=assoc_handle,claimed_id,identity,mode,ns,op_endpoint,response_nonce,return_to,signed,ns.pape,pape.auth_policies,pape.auth_level.ns.nist,pape.auth_level.nist&openid.op_endpoint=https://open.login.yahooapis.jp/openid/op/auth&openid.ns.pape=http://specs.openid.net/extensions/pape/1.0&openid.pape.auth_policies=http://schemas.openid.net/pape/policies/2007/06/none&openid.pape.auth_level.ns.nist=http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf&openid.pape.auth_level.nist=0&openid.sig=hMt8/I5rmpTnCRzr5k/qKTnQP4s%3D};

my $message = OpenID::Lite::Message->new;
for my $pair ( split /&/, $response) {
    my ($k, $v) = split /=/, $pair;
    $k =~ s/^openid\.//;
    $v = URI::Escape::uri_unescape($v);
    print '===================', "\n";
    print $k, "\n";
    print $v, "\n";
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

