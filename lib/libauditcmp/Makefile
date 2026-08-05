.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	auditcmp
SHLIB_MAJOR=	1
MAN=	libauditcmp.3
SRCS=	auditcmp.c
INCS=	auditcmp.h auditcmp_protocol.h auditcmp_server.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
