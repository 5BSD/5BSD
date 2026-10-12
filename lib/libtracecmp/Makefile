.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	tracecmp
SHLIB_MAJOR=	1
MAN=	libtracecmp.3
MLINKS+=libtracecmp.3 tracecmp_open.3
MLINKS+=libtracecmp.3 tracecmp_stats.3
MLINKS+=libtracecmp.3 tracecmp_dtrace_open.3

SRCS=	tracecmp.c tracecmp_legacy.c \
	${FIDLGEN_SRCS.tracecmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.tracecmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= TRACECMP_SCHEMA
TRACECMP_SCHEMA= tracecmp.fidl
TRACECMP_SCHEMADIR= /usr/share/fidl
TRACECMP_SCHEMAPACKAGE= libtracecmp-dev
FILESGROUPS+= TRACECMP_NOTICE
TRACECMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
TRACECMP_NOTICEDIR= /usr/share/licenses/libtracecmp/fuchsia
INCS=	tracecmp.h tracecmp_protocol.h tracecmp_server.h
LIBADD=	dtrace service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	tracecmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	tracecmp
FIDL_SCHEMAS.tracecmp=	lib/libfidl/tests/zx.fidl \
	lib/libtracecmp/tracecmp.fidl
FIDL_LIBRARY.tracecmp=	bsd.trace.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
