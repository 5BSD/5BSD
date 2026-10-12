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
MLINKS+=	libsysctlcmp.3 sysctlcmp_interfaces.3
MLINKS+=	libsysctlcmp.3 sysctlcmp_client_create.3
SRCS=	sysctlcmp.c sysctlcmp_legacy.c \
	${FIDLGEN_SRCS.sysctlcmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.sysctlcmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= SYSCTLCMP_SCHEMA
SYSCTLCMP_SCHEMA= sysctlcmp.fidl
SYSCTLCMP_SCHEMADIR= /usr/share/fidl
SYSCTLCMP_SCHEMAPACKAGE= libsysctlcmp-dev
FILESGROUPS+= SYSCTLCMP_NOTICE
SYSCTLCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
SYSCTLCMP_NOTICEDIR= /usr/share/licenses/libsysctlcmp/fuchsia
INCS=	sysctlcmp.h sysctlcmp_protocol.h sysctlcmp_server.h
LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	sysctlcmp
FIDL_SCHEMAS.sysctlcmp=	lib/libsysctlcmp/sysctlcmp.fidl
FIDL_LIBRARY.sysctlcmp=	bsd.sysctl.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
