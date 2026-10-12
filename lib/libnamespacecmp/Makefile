# SPDX-License-Identifier: BSD-2-Clause
# The system.Namespace client (bsd.namespace.v1).
.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	namespacecmp
SHLIB_MAJOR=	1
MAN=	libnamespacecmp.3
MLINKS+=	libnamespacecmp.3 service_enter_namespace.3
MLINKS+=	libnamespacecmp.3 service_enter_namespace_ex.3
MLINKS+=	libnamespacecmp.3 service_destroy_namespace.3
MLINKS+=	libnamespacecmp.3 service_namespace_info.3
SRCS=	namespacecmp.c \
	${FIDLGEN_SRCS.namespacecmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.namespacecmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= NAMESPACECMP_SCHEMA
NAMESPACECMP_SCHEMA= namespacecmp.fidl
NAMESPACECMP_SCHEMADIR= /usr/share/fidl
NAMESPACECMP_SCHEMAPACKAGE= libnamespacecmp-dev
FILESGROUPS+= NAMESPACECMP_NOTICE
NAMESPACECMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
NAMESPACECMP_NOTICEDIR= /usr/share/licenses/libnamespacecmp/fuchsia
INCS=	namespacecmp.h
LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/sys
STATIC_CFLAGS+=	${PICFLAG}

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	namespacecmp
FIDL_SCHEMAS.namespacecmp=	lib/libfidl/tests/zx.fidl \
	lib/libnamespacecmp/namespacecmp.fidl
FIDL_LIBRARY.namespacecmp=	bsd.namespace.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
