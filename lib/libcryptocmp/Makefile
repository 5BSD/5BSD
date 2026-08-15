.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	cryptocmp
SHLIB_MAJOR=	1
SRCS=	cryptocmp.c
INCS=	cryptocmp.h cryptocmp_protocol.h
LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests
.include <bsd.lib.mk>
