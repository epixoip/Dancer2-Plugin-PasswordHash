use strict;
use warnings;
use Test::More tests => 3;
use Dancer2;
use Dancer2::Plugin::PasswordHash;

my $pass = "Password1";
my $hash = password_hash($pass);

like($hash, qr/^\$PF2\$/, 'generate hash');
ok(password_matches($pass, $hash), 'validate hash');
ok(!password_matches("WrongPassword", $hash), 'incorrect password');
