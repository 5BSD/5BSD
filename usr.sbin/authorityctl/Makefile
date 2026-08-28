.include <src.opts.mk>

PACKAGE=authorityctl
PROG=	authorityctl
MAN=	authorityctl.8

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/lib/libauthorityctl
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
LIBADD=		authorityctl

.include <bsd.prog.mk>
