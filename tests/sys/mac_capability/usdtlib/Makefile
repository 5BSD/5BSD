# A shared object with a USDT provider for capprotect_dtrace_test.sh, which
# the fixture dlopen()s after its first registration.  libdtrace finds an
# object's DOF through its __SUNW_dof symbol, so the object keeps it.
PACKAGE=	tests
SHLIB=		capprotect_usdt
SHLIB_NAME=	libcapprotect_usdt.so
SHLIB_MAJOR=	1

WITHOUT_STATIC=
WITHOUT_PROFILE=
WITHOUT_PIC=

.include <src.opts.mk>

SRCS=		capprotect_usdt_lib.c
.if ${MK_DTRACE} != "no"
SRCS+=		capprotect_usdt_lib_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif
STRIP=
# bsd.lib.mk links shared objects with -x, which drops the local __SUNW_dof
# symbol; LDADD comes last on the link line and keeps it.
LDADD+=		-Wl,--discard-none

# SHLIBDIR, not LIBDIR: dtrace -G finds drti.o under LIBDIR.
SHLIBDIR=	${TESTSBASE}/sys/mac_capability

.include <bsd.lib.mk>
