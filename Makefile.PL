use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  VERSION   => '0.01',
  PREREQ_PM => {
    'Mojolicious' => '4.63',
    'Net::DHCP' => '0.693',
    'Proc::PID::File' => '0',
  },
  test      => {TESTS => 't/*.t'}
);
