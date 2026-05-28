.include <src.opts.mk>

PACKAGE=runtime
PROG=	oracled
MAN=	oracled.8
SRCS=	oracled.c event.c isolation.c proc.c

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		util

.include <bsd.prog.mk>
