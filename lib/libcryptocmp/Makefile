.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	cryptocmp
SHLIB_MAJOR=	1
MAN=	libcryptocmp.3
MLINKS+=	libcryptocmp.3 cryptocmp_open.3
MLINKS+=	libcryptocmp.3 cryptocmp_close.3
MLINKS+=	libcryptocmp.3 cryptocmp_generate.3
MLINKS+=	libcryptocmp.3 cryptocmp_generate_key.3
MLINKS+=	libcryptocmp.3 cryptocmp_digest.3
MLINKS+=	libcryptocmp.3 cryptocmp_random.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_create.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_lease.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_rotate.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_delete.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_stat.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_list.3
MLINKS+=	libcryptocmp.3 cryptocmp_client_create.3
SRCS=	cryptocmp.c \
	${FIDLGEN_SRCS.cryptocmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.cryptocmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= CRYPTOCMP_SCHEMA
CRYPTOCMP_SCHEMA= cryptocmp.fidl
CRYPTOCMP_SCHEMADIR= /usr/share/fidl
CRYPTOCMP_SCHEMAPACKAGE= libcryptocmp-dev
FILESGROUPS+= CRYPTOCMP_NOTICE
CRYPTOCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
CRYPTOCMP_NOTICEDIR= /usr/share/licenses/libcryptocmp/fuchsia
INCS=	cryptocmp.h cryptocmp_protocol.h
LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests
# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	cryptocmp
FIDL_SCHEMAS.cryptocmp=	lib/libfidl/tests/zx.fidl \
	lib/libcryptocmp/cryptocmp.fidl
FIDL_LIBRARY.cryptocmp=	bsd.crypto.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
