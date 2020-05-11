#!/usr/bin/env perl

# Author: philsmd
# Date: May 2020
# License: public domain, credits go to philsmd and hashcat

use strict;
use warnings;

# iWork
# there exist two versions: iWork 09 and iWork 2013 (2014)

use Crypt::PBKDF2;
use Crypt::CBC;
use Digest::SHA qw (sha256);


#
# Examples
#

# Example1:

# $iwork$1$2$1$100000$e5eea8cf92ac364e3ba0e20be906e072$55cf3deb5886390f919edf99e3ba40dd$336e227b39149e777cf37982c6568819fc0f2e2ca87d63dd45dbc3f032b14d47fdf79cbdf4f9d028d63f18886afef7ef80f5153818f1e0708cf60f224fda0a36:hashcat

# my $iterations = 100000;

# my $salt = pack ("H*", "e5eea8cf92ac364e3ba0e20be906e072");
# my $iv   = pack ("H*", "55cf3deb5886390f919edf99e3ba40dd");
# my $data = pack ("H*", "336e227b39149e777cf37982c6568819fc0f2e2ca87d63dd45dbc3f032b14d47fdf79cbdf4f9d028d63f18886afef7ef80f5153818f1e0708cf60f224fda0a36");


# Example2:

# $iwork$1$2$1$100000$d77ce46a68697e08b76ac91de9117541$e7b72b2848dc27efed883963b00b1ac7$e794144cd2f04bd50e23957b30affb2898554a99a3accb7506c17132654e09c04bbeff45dc4f8a8a1db5fd1592f699eeff2f9a8c31b503e9631a25a344b517f7:12345678

# my $iterations = 100000;

# my $salt = pack ("H*", "d77ce46a68697e08b76ac91de9117541");
# my $iv   = pack ("H*", "e7b72b2848dc27efed883963b00b1ac7");
# my $data = pack ("H*", "e794144cd2f04bd50e23957b30affb2898554a99a3accb7506c17132654e09c04bbeff45dc4f8a8a1db5fd1592f699eeff2f9a8c31b503e9631a25a344b517f7");


# Example3:

# $iwork$1$2$1$100000$9d406f6bbb6d3798273a1352c33ed387$7dfef75b06f8cb0092802ad833d6e88c$fc4dd694e0b5fbb123d1a6f1abec30e51176e6f0d574e4988e9c82d354baa3540e2f2268d096d9e46c1080eda32ca8eb8abfeeaa01466d86706b03eb8bd5f0e5:Password

# my $iterations = 100000;

# my $salt = pack ("H*", "9d406f6bbb6d3798273a1352c33ed387");
# my $iv   = pack ("H*", "7dfef75b06f8cb0092802ad833d6e88c");
# my $data = pack ("H*", "fc4dd694e0b5fbb123d1a6f1abec30e51176e6f0d574e4988e9c82d354baa3540e2f2268d096d9e46c1080eda32ca8eb8abfeeaa01466d86706b03eb8bd5f0e5");


# Example4:

# $iwork$1$2$1$100000$c773f06bcd580e4afa35618a7d0bee39$8b241504af92416f226d0eea4bf26443$18358e736a0401061f2dca103fceb29e88606d3ec80d09841360cbb8b9dc1d2908c270d3ff4c05cf7a46591e02ff3c9d75f4582f631721a3257dc087f98f523e:password

# my $iterations = 100000;

# my $salt = pack ("H*", "c773f06bcd580e4afa35618a7d0bee39");
# my $iv   = pack ("H*", "8b241504af92416f226d0eea4bf26443");
# my $data = pack ("H*", "18358e736a0401061f2dca103fceb29e88606d3ec80d09841360cbb8b9dc1d2908c270d3ff4c05cf7a46591e02ff3c9d75f4582f631721a3257dc087f98f523e");


# Example5:

# $iwork$2$1$1$4000$736f6d6553616c74$a9d975f8b3e1bf0c388944b457127df4$09eb5d093584376001d4c94e9d0a41eb8a2993132849c5aed8e56e7bd0e8ed50ba38aced793e3480675990c828c01d25fe245cc6aa603c6cb1a0425988f1d3dc:openwall

# my $iterations = 4000;

# my $salt = pack ("H*", "736f6d6553616c74");
# my $iv   = pack ("H*", "a9d975f8b3e1bf0c388944b457127df4");
# my $data = pack ("H*", "09eb5d093584376001d4c94e9d0a41eb8a2993132849c5aed8e56e7bd0e8ed50ba38aced793e3480675990c828c01d25fe245cc6aa603c6cb1a0425988f1d3dc");


# Example6:

# $iwork$1$2$1$100000$afff1635e78f1b216bf0b458bb14d088$8321b0942500e83939c3482cf0adda6c$cece230f33dc98c5435d4f0cd74c8b1a0efcda2c3225a262a59fdc9cbf877fb7361532c4657844cf5ba1d1e277bebd94c61b95088127315a6c9359ffd520b620:áäéíóúýčďňšžť

my $iterations = 100000;

my $salt = pack ("H*", "afff1635e78f1b216bf0b458bb14d088");
my $iv   = pack ("H*", "8321b0942500e83939c3482cf0adda6c");
my $data = pack ("H*", "cece230f33dc98c5435d4f0cd74c8b1a0efcda2c3225a262a59fdc9cbf877fb7361532c4657844cf5ba1d1e277bebd94c61b95088127315a6c9359ffd520b620");


#
# Start
#

my $pbkdf2 = Crypt::PBKDF2->new
(
  hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
  iterations => $iterations,
  output_len => 16,
);

while (my $pass = <>)
{
  chomp ($pass);


  # PBKDF2-HMAC-SHA1 to compute the AES key (16 output bytes)

  my $key = $pbkdf2->PBKDF2 ($salt, $pass);


  # AES-CBC

  my $cipher = Crypt::CBC->new ({
    key         => $key,
    cipher      => "Crypt::Rijndael",
    iv          => $iv,
    literal_key => 1,
    header      => "none",
    keysize     => 16,
    padding     => "null"
  });

  my $decrypted = $cipher->decrypt ($data);


  #
  # Verify
  #

  my $raw_data = substr ($decrypted,  0, 32);
  my $checksum = substr ($decrypted, 32, 32);

  my $sha256_of_data = sha256 ($raw_data);

  if ($sha256_of_data eq $checksum)
  {
    print "Found password: '$pass'\n";

    exit (0);
  }
}

exit (1);