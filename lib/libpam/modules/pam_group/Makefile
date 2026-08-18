LIB=		pam_group
SRCS=		pam_group.c
MANNODEV=	pam_group.8

.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	pam_group_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.lib.mk>
