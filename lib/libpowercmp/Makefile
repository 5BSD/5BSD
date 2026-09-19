.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	powercmp
SHLIB_MAJOR=	1
MAN=	libpowercmp.3
MLINKS+=	libpowercmp.3 powercmp_client_open.3 \
		libpowercmp.3 powercmp_client_close.3 \
		libpowercmp.3 powercmp_states.3 \
		libpowercmp.3 powercmp_suspend.3
SRCS=	powercmp.c
INCS=	powercmp.h powercmp_protocol.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
