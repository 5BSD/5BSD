.include <src.opts.mk>

PACKAGE=	authorityctl
PROG=		authorityctl
MAN=		authorityctl.8

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt

LIBADD=		service

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
