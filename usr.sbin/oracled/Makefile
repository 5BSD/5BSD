.include <src.opts.mk>

PACKAGE=runtime
PROG=	oracled
MAN=	oracled.8
SRCS=	oracled.c cap_rt.c commands.c config.c control.c event.c proc.c
CONFS=	oracled.conf

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		ucl util

.include <bsd.prog.mk>
