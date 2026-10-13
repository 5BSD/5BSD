#
# OpenEndpointSecurity JSON event logger.
#

.include <src.opts.mk>

PACKAGE=	oes
PROG=		oeslogger
MAN=		oeslogger.8

.PATH:		${SRCTOP}/share/examples/oes
SRCS=		oeslogger.c

CFLAGS+=	-I${SRCTOP}/lib/liboes -I${.CURDIR} -DFIVEBSD_TRACE
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		oes

.if ${MK_DTRACE} != "no"
SRCS+= diagnostics_provider.d
CFLAGS+= -DWITH_DTRACE
.endif

.include <bsd.prog.mk>
