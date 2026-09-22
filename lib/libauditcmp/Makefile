.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	auditcmp
SHLIB_MAJOR=	1
MAN=	libauditcmp.3
MLINKS+=	libauditcmp.3 auditcmp_client_open.3
MLINKS+=	libauditcmp.3 auditcmp_client_prepare.3
MLINKS+=	libauditcmp.3 auditcmp_client_adopt.3
MLINKS+=	libauditcmp.3 auditcmp_submit.3
MLINKS+=	libauditcmp.3 auditcmp_stats.3
MLINKS+=	libauditcmp.3 auditcmp_client_close.3
SRCS=	auditcmp.c
INCS=	auditcmp.h auditcmp_protocol.h auditcmp_server.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
