use strict;
use warnings;

use Test::More qw(no_plan);    # last test to print
use lib 't/lib';

use OpenID::Lite::Test::Fetcher::Dummy;
use OpenID::Lite::RelyingParty::Discover::Method::HTML;
use OpenID::Lite::Identifier;

my $html_both = <<__HTML__;
<html>
<head>
<link rel="openid2.provider" href="http://example.com/provider" />
<link rel="openid2.local_id" href="http://example.com/local" />
<link rel="openid.server" href="http://example.com/server" />
<link rel="openid.delegate" href="http://example.com/delegate" />
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_op2 = <<__HTML__;
<html>
<head>
<link rel="openid2.provider" href="http://example.com/provider" />
<link rel="openid2.local_id" href="http://example.com/local" />
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_op2_no_local = <<__HTML__;
<html>
<head>
<link rel="openid2.provider" href="http://example.com/provider" />
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_op2_no_provider = <<__HTML__;
<html>
<head>
<link rel="openid2.local_id" href="http://example.com/local" />
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_op1 = <<__HTML__;
<html>
<head>
<link rel="openid.server" href="http://example.com/server" />
<link rel="openid.delegate" href="http://example.com/delegate" />
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_op1_no_local = <<__HTML__;
<html>
<head>
<link rel="openid.server" href="http://example.com/server" />
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_op1_no_provider = <<__HTML__;
<html>
<head>
<link rel="openid.delegate" href="http://example.com/delegate" />
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_complex = <<__HTML__;
<html>
<head>
<link rel="openid.server" href="http://example.com/server" />
<link rel="openid2.provider" href="http://example.com/provider" />
<link rel="openid2.local_id" href="http://example.com/local" />
<link rel="openid.delegate" href="http://example.com/delegate" />
<link rel="openid2.provider" href="http://example.com/provider2" />
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_not_xhtml = <<__HTML__;
<html>
<head>
<link rel="openid2.provider" href="http://example.com/provider">
<link rel="openid2.local_id" href="http://example.com/local">
</head>
<body>
foobarbuz
</body>
</html>
__HTML__

my $html_invalid = <<__HTML__;
<html>
<head>
<link rel="openid2.provider" href="http://example.com/provider" />
<link rel="openid2.local_id" href="http://example.com/local" />
<body>
foobarbuz
</body>
</html>
__HTML__



my $fetcher = OpenID::Lite::Test::Fetcher::Dummy->new(
    content_type => q{text/html},
    contents     => {
        'http://example.com/html_both'            => $html_both,
        'http://example.com/html_op2'             => $html_op2,
        'http://example.com/html_op2_no_local'    => $html_op2_no_local,
        'http://example.com/html_op2_no_provider' => $html_op2_no_provider,
        'http://example.com/html_op1'             => $html_op1,
        'http://example.com/html_op1_no_local'    => $html_op1_no_local,
        'http://example.com/html_op1_no_provider' => $html_op1_no_provider,
        'http://example.com/html_complex' => $html_complex,
        'http://example.com/html_not_xhtml' => $html_not_xhtml,
        'http://example.com/html_invalid' => $html_invalid,
    },
);

my $meth = OpenID::Lite::RelyingParty::Discover::Method::HTML->new(
    _fetcher => $fetcher, );

my $services = $meth->discover(
    OpenID::Lite::Identifier->normalize('http://example.com/html_both') );
is( scalar @$services, 2 );
&test_service(
    $services->[0],
    {   server_url => q{http://example.com/provider},
        claimed_id => q{http://example.com/html_both},
        local_id   => q{http://example.com/local},
    }
);
&test_service(
    $services->[1],
    {   server_url => q{http://example.com/server},
        claimed_id => q{http://example.com/html_both},
        local_id   => q{http://example.com/delegate},
    }
);

my $service_op2 = $meth->discover(
    OpenID::Lite::Identifier->normalize(q{http://example.com/html_op2}) );
&test_service(
    $service_op2->[0],
    {   server_url => q{http://example.com/provider},
        claimed_id => q{http://example.com/html_op2},
        local_id   => q{http://example.com/local},
    }
);
my $service_op2_no_local = $meth->discover(
    OpenID::Lite::Identifier->normalize(
        q{http://example.com/html_op2_no_local})
);
&test_service(
    $service_op2_no_local->[0],
    {   server_url => q{http://example.com/provider},
        claimed_id => q{http://example.com/html_op2_no_local},
        local_id   => q{http://example.com/html_op2_no_local},
    }
);

my $service_op2_no_provider = $meth->discover(
    OpenID::Lite::Identifier->normalize(
        q{http://example.com/html_op2_no_provider})
);
ok( !$service_op2_no_provider, "should fail without provider" );

my $service_op1 = $meth->discover(
    OpenID::Lite::Identifier->normalize(q{http://example.com/html_op1})
);
&test_service(
    $service_op1->[0], 
    {   server_url => q{http://example.com/server},
        claimed_id => q{http://example.com/html_op1},
        local_id   => q{http://example.com/delegate},
    },
);

my $service_op1_no_local = $meth->discover(
    OpenID::Lite::Identifier->normalize(q{http://example.com/html_op1_no_local})
);
&test_service(
    $service_op1_no_local->[0], 
    {   server_url => q{http://example.com/server},
        claimed_id => q{http://example.com/html_op1_no_local},
        local_id   => q{http://example.com/html_op1_no_local},
    },
);
my $service_op1_no_provider = $meth->discover(
    OpenID::Lite::Identifier->normalize(q{http://example.com/html_op1_no_provider})
);
ok(!$service_op1_no_provider, "should fail without provider" );


my $service_complex = $meth->discover(
    OpenID::Lite::Identifier->normalize(q{http://example.com/html_complex})
);
is(scalar @$service_complex, 2);
&test_service(
    $service_complex->[0], 
    {   server_url => q{http://example.com/provider},
        claimed_id => q{http://example.com/html_complex},
        local_id   => q{http://example.com/local},
    },
);
&test_service(
    $service_complex->[1], 
    {   server_url => q{http://example.com/server},
        claimed_id => q{http://example.com/html_complex},
        local_id   => q{http://example.com/delegate},
    },
);
my $service_not_xhtml = $meth->discover(
    OpenID::Lite::Identifier->normalize(q{http://example.com/html_not_xhtml})
);
&test_service(
    $service_not_xhtml->[0],
    {   server_url => q{http://example.com/provider},
        claimed_id => q{http://example.com/html_not_xhtml},
        local_id   => q{http://example.com/local},
    },
);
my $service_invalid = $meth->discover(
    OpenID::Lite::Identifier->normalize(q{http://example.com/html_invalid})
);
is(scalar @$service_invalid, 1);
&test_service(
    $service_invalid->[0],
    {   server_url => q{http://example.com/provider},
        claimed_id => q{http://example.com/html_invalid},
        local_id   => q{http://example.com/local},
    },
);

sub test_service {
    my ( $service, $args ) = @_;
    is( $service->url,                   $args->{server_url} );
    is( $service->claimed_identifier,    $args->{claimed_id} );
    is( $service->find_local_identifier, $args->{local_id} );
}

