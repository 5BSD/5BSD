.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	devicecmp
SHLIB_MAJOR=	1
MAN=	libdevicecmp.3
MLINKS+=	libdevicecmp.3 devicecmp_open.3
MLINKS+=	libdevicecmp.3 devicecmp_list.3
SRCS=	devicecmp.c \
	${FIDLGEN_SRCS.devicecmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.devicecmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= DEVICECMP_SCHEMA
DEVICECMP_SCHEMA= devicecmp.fidl
DEVICECMP_SCHEMADIR= /usr/share/fidl
DEVICECMP_SCHEMAPACKAGE= libdevicecmp-dev
FILESGROUPS+= DEVICECMP_NOTICE
DEVICECMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
DEVICECMP_NOTICEDIR= /usr/share/licenses/libdevicecmp/fuchsia
INCS=	devicecmp.h devicecmp_protocol.h
LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests
# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	devicecmp
FIDL_SCHEMAS.devicecmp=	lib/libfidl/tests/zx.fidl \
	lib/libdevicecmp/devicecmp.fidl
FIDL_LIBRARY.devicecmp=	bsd.device.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
