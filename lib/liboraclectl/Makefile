.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	oraclectl
SRCS=	oraclectl.c
INCS=	oraclectl.h
MAN=	liboraclectl.3

MLINKS+=	liboraclectl.3 oraclectl_open.3
MLINKS+=	liboraclectl.3 oraclectl_status.3
MLINKS+=	liboraclectl.3 oraclectl_reload.3
MLINKS+=	liboraclectl.3 oraclectl_shutdown.3

SHLIB_MAJOR=	1

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/lib/liboraclert

.include <bsd.lib.mk>
