.include <src.opts.mk>

PROG=	chroot
MAN=	chroot.8

SRCS=	chroot.c

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	rootchange_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
