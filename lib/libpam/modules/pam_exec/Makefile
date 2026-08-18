LIB=		pam_exec
SRCS=		pam_exec.c
MANNODEV=	pam_exec.8

WARNS?=	1

.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	pam_exec_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.lib.mk>
