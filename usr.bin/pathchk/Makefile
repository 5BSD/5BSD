.include <src.opts.mk>

PROG=	pathchk

.if ${MK_DTRACE} != "no"
SRCS+=	pathchk.c pathcheck_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
