.include <src.opts.mk>

PACKAGE=runtime
PROG=	cp
SRCS=	cp.c utils.c
CFLAGS+= -D_ACL_PRIVATE

HAS_TESTS=
SUBDIR.${MK_TESTS}=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	cpcopy_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
