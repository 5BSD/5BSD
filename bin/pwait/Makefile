.include <src.opts.mk>

PACKAGE=runtime
PROG=	pwait

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

SRCS=	pwait.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	processwait_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
