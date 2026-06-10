.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	capability
SHLIB_MAJOR=	1
MAN=	libcapability.3

SRCS=	capability.c
INCS=	capability.h

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys

LIBADD=	service

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
