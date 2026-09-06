.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	devicecmp
SHLIB_MAJOR=	1
MAN=	libdevicecmp.3
MLINKS+=	libdevicecmp.3 devicecmp_open.3
MLINKS+=	libdevicecmp.3 devicecmp_list.3
MLINKS+=	libdevicecmp.3 devicecmp_hello.3
SRCS=	devicecmp.c
INCS=	devicecmp.h devicecmp_protocol.h
LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests
.include <bsd.lib.mk>
