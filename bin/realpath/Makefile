.include <src.opts.mk>

PACKAGE=runtime
PROG=	realpath

.if ${MK_DTRACE} != "no"
SRCS+=	realpath.c pathresolve_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
