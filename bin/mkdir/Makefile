.include <src.opts.mk>

PACKAGE=runtime
PROG=	mkdir

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no"
SRCS+=	mkdir.c dircreate_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
