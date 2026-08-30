.include <src.opts.mk>

PACKAGE=	runtime
PROG=		authorityctl
MAN=		authorityctl.8

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt

LIBADD=		service

.include <bsd.prog.mk>
