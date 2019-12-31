package Dancer2::Plugin::PasswordHash;

use strict;
use warnings;

use Dancer2::Plugin;

# ABSTRACT: Simple, secure password hashing for Dancer2.

our $VERSION = '0.1';

my $PF_ID = 'PF2';
my $BCRYPT_ID = '2a';
my $BCRYPT_COST = 13;
my $BCRYPT_SALT_SZ = 16;

plugin_keywords qw/
    password_hash
    password_matches
/;

has format => (
    is          => 'ro',
    from_config => 1,
    default     => sub { 'Pufferfish' }
);

has pepper => (
    is          => 'ro',
    from_config => 1,
    default     => sub { '' }
);

sub load_module {
    my ($mod_name, @import) = @_;
    (my $mod_file = $mod_name) =~ s|::|/|g;

    eval {
        require $mod_file . '.pm';
        $mod_name->import(@import);
    };

    if ($@) {
        die "Failed to load module $mod_name";
    }
}

sub pufferfish {
    my ($pass, $opts) = @_;

    load_module('Crypt::Pufferfish');

    my $pf = Crypt::Pufferfish->new({
        pepper => $opts->{'pepper'},
        cost_t => $opts->{'cost_t'},
        cost_m => $opts->{'cost_m'}
    });

    return $pf->hash($pass);
}

sub hmac_bcrypt {
    my ($pass, $opts) = @_;

    load_module('Crypt::Eksblowfish::Bcrypt', qw(bcrypt en_base64));
    load_module('Digest::SHA', qw(hmac_sha512_base64));
    load_module('Crypt::URandom', qw(urandom));

    my $salt = sprintf('$%s$%02d$%s',
        $BCRYPT_ID,
        (
            ! length $opts->{'cost_t'} ? $BCRYPT_COST
            : $opts->{'cost_t'} <  4 ?  4
            : $opts->{'cost_t'} > 31 ? 31
            : $opts->{'cost_t'}
        ),
        en_base64(urandom($BCRYPT_SALT_SZ))
    );

    my $pre_hash = hmac_sha512_base64($pass, $opts->{'pepper'});

    return bcrypt($pre_hash, $salt);
}

sub password_hash {
    my ($plugin, $pass, $opts) = @_;

    my $self = $plugin->config || {};

    my $format = $opts->{'format'} || $plugin->format;

    my $cost_t = (
          $opts->{'cost_t'}            ? $opts->{'cost_t'}
        : $self->{$format}->{'cost_t'} ? $self->{$format}->{'cost_t'}
        : ''
    );

    my $cost_m = (
          $opts->{'cost_m'}                 ? $opts->{'cost_m'}
        : $self->{'Pufferfish'}->{'cost_m'} ? $self->{'Pufferfish'}->{'cost_m'}
        : ''
    );
    
    my $settings = {
        cost_t  => $cost_t,
        cost_m  => $cost_m,
        pepper  => $plugin->pepper
    };

    if ($format eq 'Pufferfish') {
        return pufferfish($pass, $settings);
    }
    elsif ($format eq 'hmac_bcrypt') {
        return hmac_bcrypt($pass, $settings);
    }
    else {
        die 'Error: hash format "'.$format.'" is unknown.'
    }
}

sub password_matches {
    my ($plugin, $pass, $valid) = @_;

    my (undef, $id, $cost_t) = split(/\$/, $valid, 4);

    if (length $id && $id eq $PF_ID) {
        load_module('Crypt::Pufferfish');

        my $pf = Crypt::Pufferfish->new({
            pepper => $plugin->pepper
        });

        return $pf->check($valid, $pass);
    }
    elsif (length $id && $id eq $BCRYPT_ID) {
        load_module('String::Compare::ConstantTime', qw(equals));
        load_module('Crypt::Eksblowfish::Bcrypt', qw(bcrypt en_base64));
        load_module('Digest::SHA', qw(hmac_sha512_base64));

        my $pre_hash = hmac_sha512_base64($pass, $plugin->pepper);
        my $hash = bcrypt($pre_hash, $valid);

        return equals($hash, $valid);
    }

    return 0;
}

1;

__END__

=head1 NAME

Dancer2::Plugin::PasswordHash - Simple, secure password hashing for Dancer2.

=head1 DESCRIPTION

TL;DR, you should use this Dancer2 plugin if your application uses passwords, as
this is the only Dancer2 plugin that properly implements secure hashing.

This simple and elegant plugin handles secure password hashing for Dancer2 apps.
It uses the PHC finalist L<Pufferfish V2|https://github.com/epixoip/pufferfish> algorithm by default, which is an
adaptive, cache-hard PHF designed to be a modern replacement for bcrypt that is
more than 128x stronger than bcrypt for the same target runtimes. However, if
you do not yet have full confidence in Pufferfish, this plugin also implements
the I<hmac_bcrypt> algorithm (bcrypt pre-hashed with hmac-sha512) as well.

This plugin automatically handles salting. It will generate a cryptographically
strong and unique salt for each hash, and embed the salt within the hash string.
You may also define an optional (but highly recommended) pepper value within
your application's configuration file for this plugin.

=head1 SYNOPSIS

    use Dancer2;
    use Dancer2::Plugin::Database;
    use Dancer2::Plugin::PasswordHash;

    post '/create' => sub {
        my $hash = password_hash(param('password'), {
            cost_t => 9
        });

        database->quick_insert('users', {
            username => param('username'),
            password => $hash
        });
    };

    post '/login' => sub {
        my $user = database->quick_select('users', {
            username => param('username')
        });

        if (password_matches(param('password'), $user->{password})) {
            session user => $user->{username};
            redirect '/protected';
        }
    };


=head1 METHODS

=head2 password_hash (I<$password>, I<%options>)

Given a scalar containing the plaintext password and an optional hashref with
configuration parameters, this method returns a scalar containing a hash string.
You should store this string in a database for later comparison.

    my $hash = password_hash($password, {
        cost_t => 8
    });

The following configuration parameters are supported:

C<format =E<gt> I<$string>>

Specify which password hash algorithm to use. Possible values are C<Pufferfish>
and C<hmac_bcrypt>. The default value is 'Pufferfish'. 

C<cost_t =E<gt> I<$int>>

The log2 iteration count, or the number of times the function loops over itself.
This parameter controls the computation cost (the "time cost") of the function.
I<This value must not be changed arbitrarily> - you must benchmark your application
at various values to determine the highest value that still enables you to meet
your required number of peak simultaneous authentication attempts per second.
Otherwise, just use the default value.

The default value for Pufferfish is C<6> (2^6, or 64 iterations) and values ranging
from C<0 - 63> are accepted.

The default value for hmac_bcrypt is C<13> (2^13, or 16384 iterations) and values
ranging from C<4 - 31> are accepted.

C<cost_m =E<gt> I<$int>>

The log2 size of the s-boxes in kibibytes (thousands of binary bytes.) This
parameter controls how much memory (the "memory cost") the function uses.
For example, a value of "8" would be 2^8 kibibytes (or 256 KiB.) Setting this
parameter only has an affect on Pufferfish; bcrypt will always use only 4 KiB.

Pufferfish is a cache-hard algorithm, and thus needs to run in on-chip cache
(preferably L2 cache, but L3 cache may be used where longer runtimes are
desirable.) To retain GPU resistance, this parameter should I<never> be set lower
than "7". Ideally, this value should be equal to the per-core L2 cache size of
your specific CPU:

    +----------------------------------+
    | Per-core L2 cache | cost_m value |
    |-------------------|--------------|
    | 128 KiB           | 7            |
    | 256 KiB           | 8            |
    | 512 KiB           | 9            |
    | 1 MiB             | 10           |
    +----------------------------------+

On Linux systems, B<the optimal value is automatically selected by default>, and
really should not be changed. For other operating systems, the default value of 
"8" is used as most Intel CPUs made in the past decade have 256 KiB of L2 cache.
You really should only change the default value if you are NOT using Linux AND
have an AMD CPU, or a non-x86 CPU, or a really new (2018-) Intel CPU, or it is
the year 2040 and cache structures have dramatically changed in some way.

You may also set a slightly higher value in order to push out into L3 cache if
you are targeting longer runtimes. However, you are strongly encouraged to keep
Pufferfish in L2 cache unless you are I<specifically> targeting runtimes E<gt> 1000ms.
That said, you are B<strongly discouraged> from pushing out beyond L3 cache into
off-chip memory unless you I<really> know what you are doing (and you don't.)

B<TL;DR, don't change this value.>

=head2 password_matches (I<$password>, I<$hash>)

Given two scalars containing the plaintext password and the valid password hash
from the database, this method compares the hash of the password against the
valid hash in constant time. It returns C<1> if the password is correct, or C<0>
if the password is incorrect.

    if (password_matches($password, $valid)) {
        # authentication successful
    }


=head1 YAML CONFIGURATION

You may define global settings for this plugin in your application's C<config.yml>
or similar YAML configuration file. All calls to C<password_hash> will use the
default settings specified in the configuration file unless they are overridden
by passing a hashref to C<password_hash> with the appropriate keys and values.

You may also define a pepper (site-specific secret) in the application config
file. A pepper is similar to a salt, in that it is hashed along with the
plaintext password. However, while salts are unique per-hash and stored along-
side the hash, the pepper is shared amongst all hashes and must be stored
separately from the salt and the hash. A pepper makes it virtually impossible
for an attacker to crack even a single hash from your database unless they are
also able to obtain the pepper value, no matter how weak the passwords may be. 

=head2 Example config for Pufferfish

    plugins:
        PasswordHash:
            algorithm: 'Pufferfish'
            Pufferfish:
                cost_t: 9
                cost_m: 8
                pepper: '4nqYGMFJ5f4322kR'

=head2 Example config for hmac_bcrypt

    plugins:
        PasswordHash:
            algorithm: 'hmac_bcrypt'
            hmac_bcrypt:
                cost_t: 15
                pepper: '8kNTCVMmhZkXwWrY'

=head1 KNOWN ISSUES

None.

=head1 SEE ALSO

L<Dancer2>, L<Crypt::Pufferfish>, L<Crypt::Eksblowfish::Bcrypt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2019 Jeremi M Gosney <jgosney@terahash.com>.

This is free software; you can redistribute it and/or modify it under
the terms of the Simplified BSD License.

=cut
