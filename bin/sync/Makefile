.include <src.opts.mk>

PACKAGE=runtime
PROG=	sync
MAN=	sync.8

.if ${MK_DTRACE} != "no"
SRCS+=	sync.c flushall_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
