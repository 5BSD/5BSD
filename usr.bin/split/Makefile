.include <src.opts.mk>

PROG=	split

LIBADD=	util

HAS_TESTS=		yes
SUBDIR.${MK_TESTS}+=	tests

SRCS=	split.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	splitio_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
