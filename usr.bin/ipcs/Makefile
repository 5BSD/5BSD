.include <src.opts.mk>

PROG=	ipcs
SRCS=	ipcs.c ipc.c
LIBADD=	kvm

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	ipcsnapshot_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
