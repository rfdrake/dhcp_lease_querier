use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  VERSION   => '0.01',
  PREREQ_PM => {'Mojolicious' => '4.63', 'Net::DHCP' => '0.693' },
  test      => {TESTS => 't/*.t'}
);
