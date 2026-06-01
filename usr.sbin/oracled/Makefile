.include <src.opts.mk>

PACKAGE=oracled
PROG=	oracled
MAN=	oracled.8
SRCS=	oracled.c bootstrap.c cap_rt_setup.c cap_rt_claims.c cap_rt_mint.c \
	cap_rt_coal.c commands.c config.c control.c event.c oracle_proto.c \
	proc.c
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
