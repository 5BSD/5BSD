.include <src.opts.mk>

PACKAGE=	runtime

PROG=	limits
LIBADD=	util

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no"
SRCS+=	limits.c limittool_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
