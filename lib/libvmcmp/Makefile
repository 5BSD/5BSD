# SPDX-License-Identifier: BSD-2-Clause
# The system.VM client (formerly part of libservice).
.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	vmcmp
SHLIB_MAJOR=	1
MAN=	libvmcmp.3
MLINKS+=	libvmcmp.3 service_vsock_listen.3
MLINKS+=	libvmcmp.3 service_vsock_connect.3
MLINKS+=	libvmcmp.3 service_vsock_list.3
SRCS=	vmcmp.c
INCS=	vmcmp.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys
STATIC_CFLAGS+=	${PICFLAG}

.include <bsd.lib.mk>
