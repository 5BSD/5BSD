.include <src.opts.mk>

PROG=	killall
LIBADD=	jail

.if ${MK_DTRACE} != "no"
SRCS+=	killall.c signalall_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
