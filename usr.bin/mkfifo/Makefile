.include <src.opts.mk>

PROG=	mkfifo

.if ${MK_DTRACE} != "no"
SRCS+=	mkfifo.c fifocreate_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
