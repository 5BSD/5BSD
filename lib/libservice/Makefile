.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	service
SHLIB_MAJOR=	1
MAN=	libservice.3

SRCS=	libservice.c
INCS=	libservice.h component_session.h service_bootstrap.h

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/liboraclert

.include <bsd.lib.mk>
