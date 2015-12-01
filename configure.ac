dnl
dnl Copyright (c) 2004, Stefan Walter
dnl All rights reserved.
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl
dnl     * Redistributions of source code must retain the above
dnl       copyright notice, this list of conditions and the
dnl       following disclaimer.
dnl     * Redistributions in binary form must reproduce the
dnl       above copyright notice, this list of conditions and
dnl       the following disclaimer in the documentation and/or
dnl       other materials provided with the distribution.
dnl     * The names of contributors to this software may not be
dnl       used to endorse or promote products derived from this
dnl       software without specific prior written permission.
dnl
dnl THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
dnl "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
dnl LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
dnl FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
dnl COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
dnl INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
dnl BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
dnl OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
dnl AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
dnl OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
dnl THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
dnl DAMAGE.

# Process this file with autoconf to produce a configure script.
AC_INIT(jailutils, 1.7, stef@memberwebs.com)
AM_INIT_AUTOMAKE(jailutils, 1.7)

AC_CONFIG_SRCDIR([src/killjail.c])
AM_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Debug mode
AC_ARG_ENABLE(debug,
	    AC_HELP_STRING([--enable-debug],
	    [Compile binaries in debug mode]))

if test "$enable_debug" = "yes"; then
  CFLAGS="$CFLAGS -g -O0"
  AC_DEFINE_UNQUOTED(_DEBUG, 1, [In debug mode])
  echo "enabling debug compile mode"
fi

# Static compilation
AC_ARG_ENABLE(static,
	    AC_HELP_STRING([--enable-static],
	    [Compile binaries in debug mode]))

if test "$enable_static" = "yes"; then
  CFLAGS="$CFLAGS -static"
  echo "enabling static compile mode"
fi

# IPV6 enabled
AC_ARG_ENABLE(ipv6,
		AC_HELP_STRING([--disable-ipv6],
		[Disable IPV6 support]))

if test "$enable_ipv6" != "no"; then
	AC_DEFINE_UNQUOTED(HAVE_INET6, 1, [Have IPV6 Support])
	echo "enabling ipv6 support"
fi

# Checks for libraries.
AC_CHECK_LIB([kvm], [kvm_open], ,
	[ echo "ERROR: Must have FreeBSD 4.x or higher"; exit 1])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([syslog.h path.h fcntl.h limits.h sys/param.h])

# Check for jail stuff and figure out jail capabilities
AC_CHECK_LIB([c], [jail], ,
	[ echo "ERROR: Must have jail capabilities (FreeBSD 4.x or higher)"; exit 1])
AC_CHECK_LIB([c], [jail_attach],
	[ JAIL_ATTACH=yes; ], )
AC_CHECK_MEMBER([struct jail.ips],
	[ JAIL_MULTIPATCH=yes; AC_DEFINE_UNQUOTED(JAIL_MULTIPATCH, 1, [Patched Multiple IP support])], [],
[[
#include <sys/types.h>
#include <sys/param.h>
#include <sys/jail.h>
]])
AC_CHECK_MEMBER([struct jail.ip4s],
	[ JAIL_MULTIADDR=yes; AC_DEFINE_UNQUOTED(JAIL_MULTIADDR, 1, [Freebsd 7.2 Multiple IP support])], [],
[[
#include <sys/types.h>
#include <sys/param.h>
#include <sys/jail.h>
]])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_TYPE_OFF_T

# Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([strerror strstr memmove])
AC_FUNC_MALLOC

AC_STRUCT_TM

if test "$JAIL_ATTACH" = "yes"; then
	SRC_SUB=srcx
else
	SRC_SUB=src
fi

AC_SUBST([SRC_SUB])
AC_CONFIG_FILES([Makefile src/Makefile srcx/Makefile])
AC_OUTPUT

if test "$JAIL_ATTACH" = "yes"; then
    echo "Your version of FreeBSD (5.1+) supports the new utilities."
else
    echo "Your version of FreeBSD (4.0 - 5.0) only supports the old utilities"
fi

if test "$JAIL_MULTIPATCH" = "yes"; then
    echo "Your version of FreeBSD supports multiple IPs per jail via the patch."
fi

