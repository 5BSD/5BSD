#
# OpenEndpointSecurity JSON event logger.
#

PACKAGE=	oes
PROG=		oeslogger
MAN=		oeslogger.8

.PATH:		${SRCTOP}/share/examples/oes
SRCS=		oeslogger.c

CFLAGS+=	-I${SRCTOP}/lib/liboes
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		oes

.include <bsd.prog.mk>
