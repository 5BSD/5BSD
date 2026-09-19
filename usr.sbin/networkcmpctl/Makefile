.include <src.opts.mk>

PACKAGE=	bsdnetwork
PROG=		networkcmpctl
MAN=		networkcmpctl.8

CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
LIBADD=		networkcmp

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>
