.include <src.opts.mk>

PACKAGE=	runtime
PROG=	fsync

SRCS=	fsync.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	filesync_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
