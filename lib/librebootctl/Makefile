.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	rebootctl
SHLIB_MAJOR=	1
MAN=	librebootctl.3
MLINKS+=	librebootctl.3 rebootctl_notification_decode.3
SRCS=	rebootctl.c
INCS=	rebootctl.h rebootctl_protocol.h rebootctl_server.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
