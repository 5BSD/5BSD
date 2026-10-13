.include <src.opts.mk>

PROG=	renice
MAN=	renice.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no"
SRCS+=	renice.c priorityop_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
