.include <src.opts.mk>

PACKAGE= runtime
PROG=	tee

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

SRCS=	tee.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	teeio_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
