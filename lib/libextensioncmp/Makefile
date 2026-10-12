# SPDX-License-Identifier: BSD-2-Clause
# The system.SystemExtension client (formerly part of libservice).
.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	extensioncmp
SHLIB_MAJOR=	1
MAN=	libextensioncmp.3
MLINKS+=	libextensioncmp.3 service_session_extension_load.3
MLINKS+=	libextensioncmp.3 service_session_extension_stat.3
MLINKS+=	libextensioncmp.3 service_session_extension_list.3
MLINKS+=	libextensioncmp.3 service_session_extension_reload.3
MLINKS+=	libextensioncmp.3 service_session_extension_manage.3
MLINKS+=	libextensioncmp.3 service_session_extension_info.3
MLINKS+=	libextensioncmp.3 service_ensure_extension.3
MLINKS+=	libextensioncmp.3 service_extension_stat.3
MLINKS+=	libextensioncmp.3 service_extension_list.3
SRCS=	extensioncmp.c extension_session.c
INCS=	extensioncmp.h
LIBADD=	service
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys
STATIC_CFLAGS+=	${PICFLAG}

.include <bsd.lib.mk>
