#!/bin/bash
#This produces the makefiles and the configure-script.

SOURCE=.
ACLOCAL=aclocal
AUTOHEADER=autoheader
AUTOCONF=autoconf
AUTOMAKE="automake --add-missing --copy"

GENERATE="$SOURCE/generate.sh"
CONFIGURE="$SOURCE/configure"

VERSIONFILE="$SOURCE/version"
CONFIGURE_IN="${CONFIGURE}.in"

#test if help is desired
for beta in $*
do
  if test $beta == "--help" && test -a $CONFIGURE; then
    $CONFIGURE $*
    exit 0;
  fi
done

#reading the version information
. $VERSIONFILE
sed -i -e "s/AC_INIT.*/AC_INIT($NAME,$VERSION,$MAINTAINER)/" $CONFIGURE_IN

echo "Creating required files.."
#$GENERATE
echo "Executing.."
for cmd in "$ACLOCAL" "$AUTOHEADER" "$AUTOCONF" "$AUTOMAKE"
do
  echo "  $cmd"
  $cmd
  if test $? != 0; then
    echo "return value: $?";
    exit 1
  fi
done

#exec the configure
echo "Configuring.."
$CONFIGURE $*
