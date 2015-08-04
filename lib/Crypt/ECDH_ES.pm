package Crypt::ECDH_ES;

use strict;
use warnings;

use Carp;
use Crypt::Curve25519;
use Crypt::Rijndael;
use Digest::SHA qw/sha256 hmac_sha256/;

use Exporter 5.57 'import';
our @EXPORT_OK = qw/ecdhes_encrypt ecdhes_decrypt ecdhes_generate_key/;
our %EXPORT_TAGS = (all => \@EXPORT_OK);

{
	open my $urandom, '<:raw', '/dev/urandom' or croak 'Couldn\'t open /dev/urandom';
	sub _csprng {
		my $count = shift;
		read $urandom, my $ret, $count or croak "Couldn't read from csprng: $!";
		return $ret;
	}
};

my $format = 'C2 a32 a32 a*';

sub ecdhes_encrypt {
	my ($public_key, $data) = @_;

	my $private = curve25519_secret_key(_csprng(32));
	my $public  = curve25519_public_key($private);
	my $shared  = curve25519_shared_secret($private, $public_key);

	my ($encrypt_key, $sign_key) = unpack 'A16 A16', sha256($shared);
	my $iv     = substr sha256($public), 0, 16;
	my $cipher = Crypt::Rijndael->new($encrypt_key, Crypt::Rijndael::MODE_CBC);
	$cipher->set_iv($iv);

	my $pad_length = 16 - length($data) % 16;
	my $padding = pack 'C*', ($pad_length) x $pad_length;

	my $ciphertext = $cipher->encrypt($data . $padding);
	my $mac = hmac_sha256($iv . $ciphertext, $sign_key);
	return pack $format, 1, 0, $public, $mac, $ciphertext;
}

sub ecdhes_decrypt {
	my ($private_key, $packed_data) = @_;

	my ($major, undef, $public, $mac, $ciphertext) = unpack $format, $packed_data;
	croak 'Unknown format version' if $major != 1;

	my $shared = curve25519_shared_secret($private_key, $public);
	my ($encrypt_key, $sign_key) = unpack 'A16 A16', sha256($shared);
	my $iv     = substr sha256($public), 0, 16;
	croak 'MAC is incorrect' if hmac_sha256($iv . $ciphertext, $sign_key) ne $mac;
	my $cipher = Crypt::Rijndael->new($encrypt_key, Crypt::Rijndael::MODE_CBC);
	$cipher->set_iv($iv);

	my $plaintext = $cipher->decrypt($ciphertext);
	my $padding_length = ord substr $plaintext, -1;
	substr $plaintext, -$padding_length, $padding_length, '';
	return $plaintext;
}

sub ecdhes_generate_key {
	open my $fh, '<:raw', '/dev/random' or croak "Couldn't open /dev/random: $!";
	read $fh, my $buf, 32 or croak "Can't read from /dev/random: $!";
	close $fh;
	my $secret = curve25519_secret_key($buf);
	my $public = curve25519_public_key($secret);
	return ($secret, $public);
}

1;

#ABSTRACT: A fast and small hybrid crypto system

=head1 SYNOPSIS

 my $ciphertext = ecdhes_encrypt($data, $key);
 my $plaintext = ecdhes_decrypt($ciphertext, $key);

=head1 DESCRIPTION

This module uses elliptic curve cryptography in an ephemerical-static configuration combined with the AES cipher to achieve a hybrid cryptographical system. Both the public and the private key are simply 32 byte blobs.

=head2 Use-cases

You may want to use this module when storing sensive data in such a way that the encoding side can't read it afterwards, for example a website storing credit card data in a database that will be used by a separate back-end financial processor. When used in this way, a leak of the database and keys given to the website will not leak those credit card numbers.

=head2 DISCLAIMER

This distribution comes with no warranties whatsoever. While the author believes he's at least somewhat clueful in cryptography and it based on a well-understood model (ECIES), he is not a profesional cryptographer. Users of this distribution are encouraged to read the source of this distribution and its dependencies to make their own, hopefully well-informed, assesment of the security of this cryptosystem.

=head2 TECHNICAL DETAILS

This modules uses Daniel J. Bernstein's curve25519 (also used by OpenSSH) to perform a Diffie-Hellman key agreement between an encoder and a decoder. The keys of the decoder should be known in advance (as this system works as a one-way communication mechanism), for the encoder a new keypair is generated for every encryption using the system's cryptographically secure pseudo-random number generator. The shared key resulting from the key agreement is hashed and used to encrypt the plaintext using AES in CBC mode (with the IV deterministically derived from the public key). It also adds a HMAC, with the key derived from the same shared secret as the encryption key.

All cryptographic components are believed to provide at least 128-bits of security.

=func ecdhes_encrypt($public_key, $plaintext)

This will encrypt C<$plaintext> using C<$public_key>. This is a probabilistic encryption: the result will be different for every invocation.

=func ecdhes_decrypt($private_key, $ciphertext)

This will decrypt C<$ciphertext> using C<$public_key> and return the plaintext.

=func ecdhes_generate_key()

This function generates a new random curve25519 keypair and returns it as C<(private_key, $public_key)>

=head1 SEE ALSO

=over 4

=item * L<Crypt::OpenPGP|Crypt::OpenPGP>

This module can be used to achieve exactly the same effect in a more standardized way, but it requires much more infrastructure (such as a keychain), many more dependencies, larger messages and more thinking about various settings.

On the other hand, if your use-case has authenticity-checking needs that can not be solved using a MAC, you may want to use it instead of Crypt::ECDH_ES.

=item * L<Crypt::Ed25519|Crypt::Ed25519>

This is a public key signing/verification system based on an equivalent curve.

=back