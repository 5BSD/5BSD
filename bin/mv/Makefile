.include <src.opts.mk>

PACKAGE=runtime
PROG=	mv
SRCS=	mv.c

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no"
SRCS+=	moveio_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
