.include <src.opts.mk>

PACKAGE=runtime
PROG=	kill

.if ${MK_DTRACE} != "no"
SRCS+=	kill.c signaltool_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
