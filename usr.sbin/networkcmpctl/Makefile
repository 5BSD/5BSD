.include <src.opts.mk>

PACKAGE=	localnetwork
PROG=		networkcmpctl
MAN=		networkcmpctl.8

CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
LIBADD=		networkcmp

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>
