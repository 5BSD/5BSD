.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	devicecmp
SHLIB_MAJOR=	1
SRCS=	devicecmp.c
INCS=	devicecmp.h devicecmp_protocol.h
LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests
.include <bsd.lib.mk>
