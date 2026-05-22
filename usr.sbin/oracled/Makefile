.include <src.opts.mk>

PACKAGE=runtime
PROG=	oracled
MAN=	oracled.8
SRCS=	oracled.c event.c proc.c

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

LIBADD=		util

.include <bsd.prog.mk>
