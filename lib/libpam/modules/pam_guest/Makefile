LIB=		pam_guest
SRCS=		pam_guest.c
MANNODEV=	pam_guest.8

.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=	pam_guest_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.lib.mk>
