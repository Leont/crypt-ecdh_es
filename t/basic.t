#! perl

use strict;
use warnings;

use Test::More;

use Crypt::CurveAES ':all';

my $original = 'Blabla';

my $ciphertext = curveaes_encrypt(pack('H*', '87558542bbbfff0f93902ffa8434b44235daa830ccffb1a6b5300b3cda701d05'), $original);

my $plaintext = curveaes_decrypt(pack('Cx31', 42), $ciphertext);

is($plaintext, $original, 'decrypted ciphertext is identical to original');

done_testing;
