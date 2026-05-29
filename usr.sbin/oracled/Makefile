.include <src.opts.mk>

PACKAGE=oracled
PROG=	oracled
MAN=	oracled.8
SRCS=	oracled.c cap_rt.c commands.c config.c control.c event.c proc.c
CONFS=	oracled.conf

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		ucl util

.if ${MK_DTRACE} != "no"
SRCS+=		oracled_provider.d
CFLAGS+=	-I${.OBJDIR}
.endif

.include <bsd.prog.mk>
