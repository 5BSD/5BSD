.include <src.opts.mk>

PROG=   cpuset

LIBADD=	jail util

SYMLINKS+=	../..${BINDIR}/cpuset	/usr/bin/cpuset

.if ${MK_DTRACE} != "no"
SRCS+=	cpuset.c cpusettool_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
