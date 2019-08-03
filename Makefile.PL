use strict;
use warnings FATAL => 'all';

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Dancer2::Plugin::PasswordHash',
    VERSION_FROM     => 'lib/Dancer2/Plugin/PasswordHash.pm',
    ABSTRACT_FROM    => 'lib/Dancer2/Plugin/PasswordHash.pm',
    AUTHOR           => 'Jeremi M Gosney <jgosney@terahash.com>',
    LICENSE          => 'freebsd',
    MIN_PERL_VERSION => '5.14.2',
    PREREQ_PM => {
        'Test::More'                    => 0,
        'Test::Exception'               => 0,
        'Dancer2'                       => 0,
        'Crypt::Pufferfish'             => 0,
        'Crypt::Eksblowfish::Bcrypt'    => 0,
        'Digest::SHA'                   => 0,
        'Crypt::URandom'                => 0,
        'String::Compare::ConstantTime' => 0
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    META_MERGE => {
        resources => {
            homepage   => "https://github.com/epixoip/Dancer2-Plugin-PasswordHash",
            repository => "https://github.com/epixoip/Dancer2-Plugin-PasswordHash",
            bugtracker => "https://github.com/epixoip/Dancer2-Plugin-PasswordHash/issues"
        },
    },
);
