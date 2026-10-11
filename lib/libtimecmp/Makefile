.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	timecmp
SHLIB_MAJOR=	1
MAN=	libtimecmp.3
MLINKS+=	libtimecmp.3 timecmp_client_open.3 \
		libtimecmp.3 timecmp_client_close.3 \
		libtimecmp.3 timecmp_client_create.3 \
		libtimecmp.3 timecmp_get.3 \
		libtimecmp.3 timecmp_set.3 \
		libtimecmp.3 timecmp_adjust.3
SRCS=	timecmp.c timecmp_legacy.c \
	${FIDLGEN_SRCS.timecmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.timecmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= TIMECMP_SCHEMA
TIMECMP_SCHEMA= timecmp.fidl
TIMECMP_SCHEMADIR= /usr/share/fidl
TIMECMP_SCHEMAPACKAGE= libtimecmp-dev
FILESGROUPS+= TIMECMP_NOTICE
TIMECMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
TIMECMP_NOTICEDIR= /usr/share/licenses/libtimecmp/fuchsia
INCS=	timecmp.h timecmp_protocol.h
LIBADD=	service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	timecmp
FIDL_SCHEMAS.timecmp=	lib/libtimecmp/timecmp.fidl
FIDL_LIBRARY.timecmp=	bsd.time.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
