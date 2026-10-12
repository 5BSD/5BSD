# SPDX-License-Identifier: BSD-2-Clause
# The system.Namespace client (formerly part of libservice).
.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	namespacecmp
SHLIB_MAJOR=	1
MAN=	libnamespacecmp.3
MLINKS+=	libnamespacecmp.3 service_enter_namespace.3
MLINKS+=	libnamespacecmp.3 service_enter_namespace_ex.3
MLINKS+=	libnamespacecmp.3 service_destroy_namespace.3
MLINKS+=	libnamespacecmp.3 service_namespace_info.3
SRCS=	namespacecmp.c
INCS=	namespacecmp.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys
STATIC_CFLAGS+=	${PICFLAG}

.include <bsd.lib.mk>
