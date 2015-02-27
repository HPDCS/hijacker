#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([1.11 -Wall foreign subdir-objects])
AM_SILENT_RULES([yes])
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_AR
LT_INIT
AC_CONFIG_MACRO_DIR([m4])



# Debugging symbols or not?
CFLAGS="-O3 -lm -g"
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debugging of the platform]))

AS_IF([test "x$enable_debug" = "xyes"], [
	CFLAGS="-g3 -pg -Wall -Wextra -O0 -Wcast-align -Wpointer-arith -Wstrict-overflow=5 -Wstrict-prototypes -Winline -Wundef -Wnested-externs -Wshadow -Wunreachable-code -Wfloat-equal -Wredundant-decls -Wold-style-definition -std=c99 -fno-omit-frame-pointer -ffloat-store -fno-common -fstrict-aliasing -fgnu89-inline -rdynamic -lm"
])


#----------------------------------------------------------------------------
# Check for languages 
#----------------------------------------------------------------------------
AC_LANG([C])

#----------------------------------------------------------------------------
# Checks for programs.
#----------------------------------------------------------------------------
AM_PROG_AS
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_CC_C_O
AM_PROG_CC_C_O

#----------------------------------------------------------------------------
# Checks for C header files.
#----------------------------------------------------------------------------
AC_HEADER_STDC

#----------------------------------------------------------------------------
# Checks for LIBXML2
#----------------------------------------------------------------------------

have_libxml2="1"
AC_ARG_WITH([xml2-config], 
  AS_HELP_STRING([--with-xml2-config], [libxml2 config program]),
if test "x${with_xml2_config}" = "xno" ; then
  XML2_CONFIG=
else
  XML2_CONFIG="${with_xml2_config}"
fi
,
  XML2_CONFIG=
)
if test "x${XML2_CONFIG}" != "x" ; then
   if test ! -x "${XML2_CONFIG}" ; then
     AC_MSG_ERROR([Unusable or missing xml2-config: ${XML2_CONFIG}])
   fi
else
  AC_PATH_PROG([XML2_CONFIG], [xml2-config], , [${PATH}])
  if test "x${XML2_CONFIG}" = "x" ; then
    AC_MSG_ERROR([Cannot configure without xml2-config])
  fi
fi

# Update compiling flags to correctly link towards libxml2
CFLAGS="${CFLAGS} `${XML2_CONFIG} --cflags`"
CPPFLAGS="${CPPFLAGS} `${XML2_CONFIG} --cflags`"
LIBS="${LIBS} `${XML2_CONFIG} --libs`"

if test "x${have_libxml2}" = "x1" ; then
# Final sanity check, to make sure that used headers are present
  AC_CHECK_HEADER([libxml/xmlmemory.h], , [have_libxml2="0"])
  AC_CHECK_HEADER([libxml/parser.h], , [have_libxml2="0"])
fi
if test "x${have_libxml2}" = "x0" ; then
  AC_MSG_ERROR([Cannot build without libxml2])
fi



#
# Check for LIBZ
#

have_libz="1"
AC_CHECK_HEADERS([zlib.h], , [have_libz="0"])
AC_CHECK_LIB([z], [deflate], , [have_libz="0"])
if test "x${have_libz}" = "x0" ; then
  AC_MSG_ERROR([Cannot build without libz])
fi





AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
