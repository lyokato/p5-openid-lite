use strict;
use warnings;

use inc::Module::Install;

name 'OpenID-Lite';
all_from 'lib/OpenID/Lite.pm';

requires(
    'Mouse'                      => '0.17',
    'MouseX::Types'              => '0.01',
    'Any::Moose'                 => '0.01',
    'XRI::Resolution::Lite'      => '0.02',
    'LWPx::ParanoidAgent'        => '1.04',
    'HTTP::Request'              => 0,
    'HTML::Entities'             => 0,
    'HTML::TreeBuilder'          => 0,
    'HTML::TreeBuilder::XPath'   => '0.09',
    'XML::LibXML'                => 0,
    'String::Random'             => 0,
    'Crypt::DH::GMP'             => '0.00005',
    'Crypt::SSLeay'              => 0,
    'URI::Escape'                => 0,
    'Storable'                   => 0,
    'List::MoreUtils'            => 0,
    'Digest::SHA'                => 0,
    'URI'                        => 0,
    'Data::Dump'                 => 0,
    'LWP::UserAgent'             => 0,
    'Time::Local'                => 0,
    'Params::Validate'           => 0,
    'Math::BigInt'               => 0,
    'UNIVERSAL::require'         => 0,
);

tests('t/*.t t/*/*.t');

#author_tests('xt');
test_requires(
    'Test::More' => 0,

    #    'Test::Class' => 0,
);

auto_include;
WriteAll;
