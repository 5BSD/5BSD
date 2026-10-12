# SPDX-License-Identifier: BSD-2-Clause
# The system.SystemExtension client (bsd.extension.v1).
.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	extensioncmp
SHLIB_MAJOR=	1
MAN=	libextensioncmp.3
MLINKS+=	libextensioncmp.3 extensioncmp_session_open.3
MLINKS+=	libextensioncmp.3 extensioncmp_session_create.3
MLINKS+=	libextensioncmp.3 extensioncmp_session_close.3
MLINKS+=	libextensioncmp.3 extensioncmp_load.3
MLINKS+=	libextensioncmp.3 extensioncmp_stat.3
MLINKS+=	libextensioncmp.3 extensioncmp_list.3
MLINKS+=	libextensioncmp.3 extensioncmp_reload.3
MLINKS+=	libextensioncmp.3 extensioncmp_manage.3
MLINKS+=	libextensioncmp.3 extensioncmp_info.3
MLINKS+=	libextensioncmp.3 service_ensure_extension.3
MLINKS+=	libextensioncmp.3 service_extension_stat.3
MLINKS+=	libextensioncmp.3 service_extension_list.3
SRCS=	extensioncmp.c \
	${FIDLGEN_SRCS.extensioncmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.extensioncmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= EXTENSIONCMP_SCHEMA
EXTENSIONCMP_SCHEMA= extensioncmp.fidl
EXTENSIONCMP_SCHEMADIR= /usr/share/fidl
EXTENSIONCMP_SCHEMAPACKAGE= libextensioncmp-dev
FILESGROUPS+= EXTENSIONCMP_NOTICE
EXTENSIONCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
EXTENSIONCMP_NOTICEDIR= /usr/share/licenses/libextensioncmp/fuchsia
INCS=	extensioncmp.h
LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/sys
STATIC_CFLAGS+=	${PICFLAG}

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	extensioncmp
FIDL_SCHEMAS.extensioncmp=	lib/libextensioncmp/extensioncmp.fidl
FIDL_LIBRARY.extensioncmp=	bsd.extension.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
