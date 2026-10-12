.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	auditcmp
SHLIB_MAJOR=	1
MAN=	libauditcmp.3
MLINKS+=	libauditcmp.3 auditcmp_client_open.3
MLINKS+=	libauditcmp.3 auditcmp_client_prepare.3
MLINKS+=	libauditcmp.3 auditcmp_client_adopt.3
MLINKS+=	libauditcmp.3 auditcmp_submit.3
MLINKS+=	libauditcmp.3 auditcmp_stats.3
MLINKS+=	libauditcmp.3 auditcmp_client_close.3
SRCS=	auditcmp.c auditcmp_legacy.c \
	${FIDLGEN_SRCS.auditcmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.auditcmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= AUDITCMP_SCHEMA
AUDITCMP_SCHEMA= auditcmp.fidl
AUDITCMP_SCHEMADIR= /usr/share/fidl
AUDITCMP_SCHEMAPACKAGE= libauditcmp-dev
FILESGROUPS+= AUDITCMP_NOTICE
AUDITCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
AUDITCMP_NOTICEDIR= /usr/share/licenses/libauditcmp/fuchsia
INCS=	auditcmp.h auditcmp_protocol.h auditcmp_server.h
LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	auditcmp
FIDL_SCHEMAS.auditcmp=	lib/libauditcmp/auditcmp.fidl
FIDL_LIBRARY.auditcmp=	bsd.audit.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
