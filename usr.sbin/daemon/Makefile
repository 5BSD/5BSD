PROG=	daemon
MAN=	daemon.8

LIBADD=	util

.include <src.opts.mk>

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no"
SRCS+=	daemon.c daemonwait_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
