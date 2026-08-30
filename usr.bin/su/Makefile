.include <src.opts.mk>

PROG=	su
SRCS=	su.c

CFLAGS+=	-I${SRCTOP}/lib/libservice

.if ${MK_DTRACE} != "no"
SRCS+=		su_provider.d
CFLAGS+=	-DWITH_DTRACE
.endif

LIBADD=	util pam service channel capability capbundle
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle

.if ${MK_AUDIT} != "no"
CFLAGS+= -DUSE_BSM_AUDIT
LIBADD+=	bsm
.endif

BINOWN=	root
BINMODE=4555
PRECIOUSPROG=

.include <bsd.prog.mk>
