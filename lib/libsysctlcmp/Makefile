.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	sysctlcmp
SHLIB_MAJOR=	1
MAN=	libsysctlcmp.3
MLINKS+=	libsysctlcmp.3 sysctlcmp_client_open.3 \
		libsysctlcmp.3 sysctlcmp_client_close.3 \
		libsysctlcmp.3 sysctlcmp_get.3 \
		libsysctlcmp.3 sysctlcmp_set.3 \
		libsysctlcmp.3 sysctlcmp_oidfmt.3 \
		libsysctlcmp.3 sysctlcmp_describe.3 \
		libsysctlcmp.3 sysctlcmp_next.3
SRCS=	sysctlcmp.c
INCS=	sysctlcmp.h sysctlcmp_protocol.h sysctlcmp_server.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
