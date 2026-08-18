LIB=		pam_rhosts
SRCS=		pam_rhosts.c
MANNODEV=	pam_rhosts.8

.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	pam_rhosts_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.lib.mk>
