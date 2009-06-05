#!/usr/bin/perl

use strict;
use warnings;

use lib '../../lib';

use OpenID::Lite::Message;
use OpenID::Lite::SignatureMethods;
use MIME::Base64 qw(decode_base64 encode_base64);
use Perl6::Say;


my $response = q{openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=id_res&openid.op_endpoint=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fud&openid.response_nonce=2009-06-05T05%3A53%3A50Zr5QnRdK3EHQfuw&openid.return_to=http%3A%2F%2Fexample.com%2Freturn_to&openid.assoc_handle=AOQobUcFJ-pwwZF42uhiKYYjH0fu4WZWE9xX3MrcftsZPGq2ftgJV6bk&openid.signed=op_endpoint%2Cclaimed_id%2Cidentity%2Creturn_to%2Cresponse_nonce%2Cassoc_handle&openid.sig=rMJbvL1u9OeQ%2FDPQFezqq2uoPyc%3D&openid.identity=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fid%3Fid%3DAItOawnPdjM5hX0L4vR06KyKM59k8GDhXMGJKTQ&openid.claimed_id=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fid%3Fid%3DAItOawnPdjM5hX0L4vR06KyKM59k8GDhXMGJKTQ};

my $message = OpenID::Lite::Message->new;
for my $pair ( split /&/, $response) {
    my ($k, $v) = split /=/, $pair;
    $k =~ s/^openid\.//;
    $v = URI::Escape::uri_unescape($v);
    say $k;
    say $v;
    $message->set($k, $v);
}



my $secret = q{MobchdRPuirQdGQ7pIstU82tOfs=};
$secret = decode_base64($secret);
say $secret;
say length($secret);

my $method = OpenID::Lite::SignatureMethods->select_method('HMAC-SHA1');
say $method->verify( $secret, $message ) ? "true" : "false";

say $method->sign( $secret, $message );

