use strict;
use warnings;
use Test::More tests => 2;
use Test::Exception;
use Dancer2;
use Dancer2::Plugin::PasswordHash;

my $pass = "Password1";

throws_ok { password_hash($pass, { format => 'bogus' }) } qr/^Error: hash format/, 'bogus format';
ok(!password_matches($pass, 'bogushash'), 'invalid hash comparison');
