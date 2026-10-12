#
# OpenEndpointSecurity userland client library (liboes).
#

.include <src.opts.mk>

PACKAGE=	oes
LIB=		oes
SHLIB_MAJOR=	1
SRCS=		liboes.c broker.c ${FIDLGEN_SRCS.oes_broker}
LIBADD=		service fidl_bsd cplusplus
CXXSTD=		c++20

MAN=		liboes.3

# liboes.h installs to /usr/include; the kernel ABI header it pulls in
# (<security/oes/oes.h>, which itself includes oes_event_table.h) installs
# under /usr/include/security/oes so userland consumers resolve it.
INCSGROUPS=	INCS OESINCS
INCS=		liboes.h
OESINCS=	${SRCTOP}/sys/security/oes/oes.h \
		${SRCTOP}/sys/security/oes/oes_event_table.h
OESINCSDIR=	${INCLUDEDIR}/security/oes

CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libservice
CFLAGS+=	-I${FIDLGEN.oes_broker}
.include "../libfidl/runtime-includes.mk"

WARNS?=		6
# The generated bsd.oes.v1 bindings are not held to liboes's warning level.
.for _f in natural_types.cc common_types.cc bsd.cc
CXXWARNFLAGS.${_f}+=	-w
.endfor

FILESGROUPS+=	OES_SCHEMA OES_NOTICE
OES_SCHEMA=	oes_broker.fidl
OES_SCHEMADIR=	/usr/share/fidl
OES_SCHEMAPACKAGE=	oes
OES_NOTICE=	${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
OES_NOTICEDIR=	/usr/share/licenses/liboes/fuchsia

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	oes_broker
FIDL_SCHEMAS.oes_broker=	lib/libfidl/tests/zx.fidl \
	lib/liboes/oes_broker.fidl
FIDL_LIBRARY.oes_broker=	bsd.oes.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
