.include <src.opts.mk>

PACKAGE=runtime
PROG=	oracled
MAN=	oracled.8
SRCS=	oracled.c cap_rt.c commands.c control.c event.c proc.c

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		util

.include <bsd.prog.mk>
