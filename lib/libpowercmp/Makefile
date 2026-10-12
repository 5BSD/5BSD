.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	powercmp
SHLIB_MAJOR=	1
MAN=	libpowercmp.3
MLINKS+=	libpowercmp.3 powercmp_client_open.3 \
		libpowercmp.3 powercmp_client_close.3 \
		libpowercmp.3 powercmp_states.3 \
		libpowercmp.3 powercmp_suspend.3
MLINKS+= libpowercmp.3 powercmp_client_create.3
MLINKS+= libpowercmp.3 powercmp_inhibit.3 libpowercmp.3 powercmp_uninhibit.3 \
	libpowercmp.3 powercmp_inhibitors.3
SRCS=	powercmp.c powercmp_legacy.c \
	${FIDLGEN_SRCS.powercmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.powercmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= POWERCMP_SCHEMA
POWERCMP_SCHEMA= powercmp.fidl
POWERCMP_SCHEMADIR= /usr/share/fidl
POWERCMP_SCHEMAPACKAGE= libpowercmp-dev
FILESGROUPS+= POWERCMP_NOTICE
POWERCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
POWERCMP_NOTICEDIR= /usr/share/licenses/libpowercmp/fuchsia
INCS=	powercmp.h powercmp_protocol.h
LIBADD=	service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	powercmp
FIDL_SCHEMAS.powercmp=	lib/libpowercmp/powercmp.fidl
FIDL_LIBRARY.powercmp=	bsd.power.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
