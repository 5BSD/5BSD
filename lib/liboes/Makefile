#
# OpenEndpointSecurity userland client library (liboes).
#

PACKAGE=	oes
LIB=		oes
SHLIB_MAJOR=	2
SRCS=		liboes.c

MAN=		liboes.3

# liboes.h installs to /usr/include; the kernel ABI header it pulls in
# (<security/oes/oes.h>, which itself includes oes_event_table.h) installs
# under /usr/include/security/oes so userland consumers resolve it.
INCSGROUPS=	INCS OESINCS
INCS=		liboes.h
OESINCS=	${SRCTOP}/sys/security/oes/oes.h \
		${SRCTOP}/sys/security/oes/oes_event_table.h
OESINCSDIR=	${INCLUDEDIR}/security/oes

CFLAGS+=	-I${SRCTOP}/sys

WARNS?=		6

.include <bsd.lib.mk>
