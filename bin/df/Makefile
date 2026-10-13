.include <src.opts.mk>

PACKAGE=runtime

PROG=	df
SRCS=	df.c

LIBADD=	xo util

.if ${MK_DTRACE} != "no"
SRCS+=	diskspace_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
