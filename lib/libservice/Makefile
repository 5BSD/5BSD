.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	service
SHLIB_MAJOR=	1
MAN=	libservice.3

SRCS=	libservice.c
INCS=	libservice.h

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/usr.sbin/serviced

.include <bsd.lib.mk>
