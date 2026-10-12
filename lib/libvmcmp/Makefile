# SPDX-License-Identifier: BSD-2-Clause
# The system.VM client (bsd.vm.v1).
.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	vmcmp
SHLIB_MAJOR=	1
MAN=	libvmcmp.3
MLINKS+=	libvmcmp.3 service_vsock_listen.3
MLINKS+=	libvmcmp.3 service_vsock_connect.3
MLINKS+=	libvmcmp.3 service_vsock_list.3
SRCS=	vmcmp.c \
	${FIDLGEN_SRCS.vmcmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.vmcmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= VMCMP_SCHEMA
VMCMP_SCHEMA= vmcmp.fidl
VMCMP_SCHEMADIR= /usr/share/fidl
VMCMP_SCHEMAPACKAGE= libvmcmp-dev
FILESGROUPS+= VMCMP_NOTICE
VMCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
VMCMP_NOTICEDIR= /usr/share/licenses/libvmcmp/fuchsia
INCS=	vmcmp.h
LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/sys
STATIC_CFLAGS+=	${PICFLAG}

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	vmcmp
FIDL_SCHEMAS.vmcmp=	lib/libfidl/tests/zx.fidl \
	lib/libvmcmp/vmcmp.fidl
FIDL_LIBRARY.vmcmp=	bsd.vm.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
