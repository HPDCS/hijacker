#!/bin/sh

set -ex
rm -rf autom4te.cache aclocal.m4
find . -name "Makefile.in" -exec rm {} \;
aclocal --force

autoreconf -i
autoconf -f -W all,no-obsolete
# autoheader -f -W all
# automake -a -c -f -W all
automake --add-missing --foreign --copy -c -W all

rm -rf autom4te.cache
exit 0
