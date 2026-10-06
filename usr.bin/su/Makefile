.include <src.opts.mk>

PROG=	su
SRCS=	su.c

.if ${MK_DTRACE} != "no"
SRCS+=		su_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

LIBADD=	util pam

.if ${MK_AUDIT} != "no"
CFLAGS+= -DUSE_BSM_AUDIT
LIBADD+=	bsm
.endif

BINOWN=	root
BINMODE=4555
PRECIOUSPROG=

.include <bsd.prog.mk>
