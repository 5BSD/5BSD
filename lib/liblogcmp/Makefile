.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	logcmp
SHLIB_MAJOR=	1
MAN=	liblogcmp.3
MLINKS+=liblogcmp.3 logcmp_client_open.3
MLINKS+=liblogcmp.3 logcmp_logger_create.3
MLINKS+=liblogcmp.3 logcmp_logger_destroy.3
MLINKS+=liblogcmp.3 logcmp_emit.3
MLINKS+=liblogcmp.3 logcmp_log.3
MLINKS+=liblogcmp.3 logcmp_vlog.3
MLINKS+=liblogcmp.3 logcmp_flush.3
MLINKS+=liblogcmp.3 logcmp_stats.3
MLINKS+=liblogcmp.3 logcmp_query_next.3
MLINKS+=liblogcmp.3 logcmp_client_close.3

SRCS=	logcmp.c logcmp_wakeup.c \
	${FIDLGEN_SRCS.logcmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.logcmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= LOGCMP_SCHEMA
LOGCMP_SCHEMA= logcmp.fidl
LOGCMP_SCHEMADIR= /usr/share/fidl
LOGCMP_SCHEMAPACKAGE= liblogcmp-dev
FILESGROUPS+= LOGCMP_NOTICE
LOGCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
LOGCMP_NOTICEDIR= /usr/share/licenses/liblogcmp/fuchsia
INCS=	logcmp.h logcmp_protocol.h logcmp_server.h

LIBADD=	pthread service shmring fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	logcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	logcmp
FIDL_SCHEMAS.logcmp=	lib/libfidl/tests/zx.fidl \
	lib/liblogcmp/logcmp.fidl
FIDL_LIBRARY.logcmp=	bsd.log.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
