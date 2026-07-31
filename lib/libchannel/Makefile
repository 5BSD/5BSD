.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	channel
SHLIB_MAJOR=	1
MAN=	libchannel.3
INCS=	channel.h
SRCS=	channel.c

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys

.if ${MK_DTRACE} != "no"
SRCS+=	channel_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
