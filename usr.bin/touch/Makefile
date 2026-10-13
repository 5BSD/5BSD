.include <src.opts.mk>

PROG=	touch
HAS_TESTS=
SUBDIR.${MK_TESTS}=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	touch.c filetime_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
