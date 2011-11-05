use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::DNS::Sinkhole',
    AUTHOR              => 'Ricardo Harman <perl-cpan@richardharman.com>',
    VERSION_FROM        => 'lib/Net/DNS/Sinkhole.pm',
    ABSTRACT_FROM       => 'lib/Net/DNS/Sinkhole.pm',
    LICENSE             => 'perl',
    PL_FILES            => {},
    PREREQ_PM => {
        'Net::DNS::Nameserver' => 0,
        'Tree::Trie' => 1.8,
        'Net::DNS::Resolver::Programmable' => 0,
        'List::Util' => 0,
        'Test::More'      => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-DNS-Sinkhole-*' },
);
