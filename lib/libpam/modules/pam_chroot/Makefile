LIB=		pam_chroot
SRCS=		pam_chroot.c
MANNODEV=	pam_chroot.8

.include <src.opts.mk>
.if ${MK_DTRACE} != "no"
SRCS+=		pam_chroot_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.lib.mk>
