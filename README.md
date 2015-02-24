hijacker [![Build Status](https://travis-ci.org/HPDCS/hijacker.svg?branch=master)](https://travis-ci.org/HPDCS/hijacker)
=========

Hijacker is a static binary instrumentation tool, targeted at HPC applications. It has seen his light on
October, 18th 2012 as an ad-hoc tool to instrument executables for [ROOT-Sim](https://github.com/HPDCS/ROOT-Sim),
but has since then been extended and made more versatile.

It allows to instrument relocatable object files according to a set of rules which are specificied in an xml file.

We are porting the latest development branches from our previous repository here.
This is done in order to release a stable versione as soon as possible, but it will take some while.
In the meantime, it is possible to use this software as-is, but do not expect it to be able to apply all the rules,
as we are currently refactoring the old code.

If you are interested in the project, and would like to try it or contribute, just fork and keep in touch with us.

INSTALL
-------

There are no real dependencies for hijacker. A quick  `./configure && make && make install`
should do the job.

USAGE
-------

You can see the program's usage statement by invoking it with --help.  A
typical invocation is:

 ./hijacker -c config.xml -i relocatable.o

Alessandro Pellegrini <pellegrini@dis.uniroma1.it>
Rome, Italy

