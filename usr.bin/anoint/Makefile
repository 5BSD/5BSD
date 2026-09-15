.include <src.opts.mk>

PACKAGE=	runtime
PROG=		anoint
MAN=		anoint.1

CFLAGS+=	-I${SRCTOP}/lib/libservice
LIBADD=		service channel capability

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
