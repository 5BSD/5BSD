.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	kldmgr
SHLIB_MAJOR=	1
MAN=	libkldmgr.3
SRCS=	kldmgr.c
INCS=	kldmgr.h kldmgr_protocol.h kldmgr_server.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
