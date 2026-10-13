.include <src.opts.mk>

PACKAGE=	runtime
PROG=	du
LIBADD=	xo util

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	du.c diskwalk_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
