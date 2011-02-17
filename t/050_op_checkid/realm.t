use strict;
use warnings;

use Test::More tests => 129;
use OpenID::Lite::Realm;
use File::Spec;

sub load_list {
    my $file_name = shift;
    my $file_path = File::Spec->catfile(qw(t data realm), $file_name);
    my @lines;
    open(my $fh, '<', $file_path);
    while (my $row = <$fh>) {
        chomp $row;
        push(@lines, $row);
    }
    close($fh);
    return \@lines;
}

sub test_sanity {

    my $not_parsed = &load_list('not_parsed.txt');
    for my $u ( @$not_parsed ) {
        my $r = OpenID::Lite::Realm->parse($u);
        ok(!$r, sprintf q{%s couldn't be parsed.}, $u);
    }

    my $sane = &load_list('sane.txt');
    for my $u ( @$sane ) {
        my $r = OpenID::Lite::Realm->parse($u);
        ok($r, sprintf q{%s could be parsed.}, $u);
        ok($r->is_sane, sprintf q{%s is sane.}, $u);
        ok(OpenID::Lite::Realm->check_sanity($u), sprintf q{%s is sane.}, $u);
    }

    my $insane = &load_list('insane.txt');
    for my $u ( @$insane ) {
        my $r = OpenID::Lite::Realm->parse($u);
        ok($r, sprintf q{%s could be parsed.}, $u);
        ok(!$r->is_sane, sprintf q{%s is insane. by is_sane}, $u);
        ok(!OpenID::Lite::Realm->check_sanity($u), sprintf q{%s is insane. by check_sanity}, $u);
    }
}

sub test_match {

}

sub test_return_to_matches {

    # 11 cases
    my $cases = [
        {   allowed_urls => [],
            return_to    => undef,
            expected     => 0,
        },
        {   allowed_urls => [],
            return_to    => q{},
            expected     => 0,
        },
        {   allowed_urls => [],
            return_to    => q{http://bogus/return_to},
            expected     => 0,
        },
        {   allowed_urls => [q{http://bogus/}],
            return_to    => undef,
            expected     => 0,
        },
        {   allowed_urls => [q{://broken/}],
            return_to    => undef,
            expected     => 0,
        },
        {   allowed_urls => [q{://broken/}],
            return_to    => q{http://broken/},
            expected     => 0,
        },
        {   allowed_urls => [q{http://*.broken/}],
            return_to    => q{http://foo.broken/},
            expected     => 0,
        },
        {   allowed_urls => [q{http://x.broken/}],
            return_to    => q{http://foo.broken/},
            expected     => 0,
        },
        {   allowed_urls => [ q{http://first/}, q{http://second/path/} ],
            return_to => q{http://second/?query=x},
            expected  => 0,
        },
        {   allowed_urls => [q{http://broken/}],
            return_to    => q{http://broken/},
            expected     => 1,
        },
        {   allowed_urls => [ q{http://first/}, q{http://second/} ],
            return_to    => q{http://second/?query=x},
            expected     => 1,
        },
    ];
    for my $case (@$cases) {
        $case->{return_to} ||= '';
        my $result
            = OpenID::Lite::Realm->return_to_matches( $case->{allowed_urls},
            $case->{return_to} );
        is( $result, $case->{expected}, sprintf(q{return_to_matches failed with "%s"}, $case->{return_to}) );
    }
}

sub test_build_discovery_url {
    # 4 cases
    my $cases = [
        {   realm         => q{http://foo.com/path},
            discovery_url => q{http://foo.com/path}, },
        {   realm         => q{http://foo.com/path?foo=bar},
            discovery_url => q{http://foo.com/path?foo=bar}, },
        {   realm         => q{http://*.bogus.com/path},
            discovery_url => q{http://www.bogus.com/path}, },
        {   realm         => q{http://*.bogus.com:122/path},
            discovery_url => q{http://www.bogus.com:122/path}, },
    ];
    for my $case (@$cases) {
        my $r = OpenID::Lite::Realm->parse( $case->{realm} );
        ok($r);
        is( $r->build_discovery_url, $case->{discovery_url},
            sprintf("discovery_url failed with %s and %s", $case->{discovery_url}, $case->{realm}));
    }
}

&test_sanity();
&test_return_to_matches();
&test_build_discovery_url();

