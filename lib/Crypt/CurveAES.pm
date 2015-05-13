package Crypt::CurveAES;

use strict;
use warnings;

use Carp;
use Crypt::Curve25519;
use Crypt::CBC;
use Crypt::Rijndael;

use Exporter 5.57 'import';
our @EXPORT_OK = qw/curveaes_encrypt curveaes_decrypt curveaes_generate_key/;
our %EXPORT_TAGS = (all => \@EXPORT_OK);

{
	open my $urandom, '<:raw', '/dev/urandom' or croak 'Couldn\'t open /dev/urandom';
	read $urandom, my $key, 16 or croak "Couldn't read random key for prng: $!";
	my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CTR);
	read $urandom, my $iv, 16 or croak "Couldn't read random iv for cipher: $!";
	$cipher->set_iv($iv);
	close $urandom;
	sub _csprng {
		my $count = shift;
		return $cipher->encrypt("\0" x $count);
	}
};

my $format = 'C2 a32 a16 w/a';

sub curveaes_encrypt {
	my ($key, $data) = @_;

	my $private = curve25519_secret_key(_csprng(32));
	my $public  = curve25519_public_key($private);
	my $shared  = curve25519_shared_secret($private, $key);

	my $iv      = _csprng(16);
	my $cipher = Crypt::CBC->new(
		-key         => $shared,
		-literal_key => 1,
		-cipher      => 'Rijndael',
		-header      => 'none',
		-iv          => $iv,
	);
	return pack $format, 1, 0, $public, $iv, $cipher->encrypt($data), '';
}

sub curveaes_decrypt {
	my ($key, $data) = @_;

	my ($major, $minor, $public, $iv, $ciphertext) = unpack $format, $data;
	croak 'Unknown format version for ciphertext' if $major != 1;

	my $cipher = Crypt::CBC->new(
		-key         => curve25519_shared_secret($key, $public),
		-literal_key => 1,
		-cipher      => 'Rijndael',
		-header      => 'none',
		-iv          => $iv,
	);
	return $cipher->decrypt($ciphertext);
}

sub curveaes_generate_key {
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

 my $ciphertext = curveaes_encrypt($data, $key);
 my $plaintext = curveaes_decrypt($ciphertext, $key);

=head1 DESCRIPTION

This module uses elliptic curve cryptography combined with the AES-256 cipher to achieve an hybrid cryptographical system. Both the public and the private key are simply 32 byte blobs.

=head2 Use-cases

You may want to use this module when storing sensive data in such a way that the encoding side can't read it afterwards, for example a website storing credit card data in a database that will be used by a separate back-end financial processor. When used in this way, a leak of the database and keys given to the website will not leak those credit card numbers.

=head2 DISCLAIMER

This distribution comes with no warranties whatsoever. While the author believes he's at least somewhat clueful in cryptography, he is not a profesional cryptographer. Users of this distribution are encouraged to read the source of this distribution and its dependencies to make their own, hopefully well-informed, assesment of the security of this cryptosystem.

=head2 TECHNICAL DETAILS

This modules uses Daniel J. Bernstein's Curve25519 to perform a Diffie-Hellman key agreement between an encoder and a decoder. The keys of the decoder should be known in advance (as this system works as a one-way communication mechanism), for the encoder a new keypair is generated for every encryption using a cryptographically secure pseudo-random number generator based on AES in CTR mode. The shared key resulting from the key agreement is used to encrypt the plaintext using AES (or another cipher if you ask for it) in CBC mode.

This module does not provide any authentication, if you require this you either want to add an MAC or a signature.

=func curveaes_encrypt($public_key, $plaintext)

This will encrypt C<$plaintext> using C<$public_key>. The result will be different for every invocation.

=func curveaes_decrypt($private_key, $ciphertext)

This will decrypt C<$ciphertext> using C<$public_key>.

=func curveaes_generate_key()

=HEAD1 SEE ALSO

=over 4

=item * Crypt::OpenPGP

This module can be used to achieve exactly the same effect in a more standardized way, but it requires much more infrastructure (such as a keychain), many more dependencies and more thinking about various settings.

On the other hand, if your use-case has authenticity-checking needs that can not be solved using a MAC, you may want to use it instead of Crypt::CurveAES.

=back
