.include <src.opts.mk>

PACKAGE=	runtime
PROG=		tzfsctl
MAN=		tzfsctl.8

CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libtzfsd
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/sys

LIBADD=		tzfsd trustedzfs

.include <bsd.prog.mk>
