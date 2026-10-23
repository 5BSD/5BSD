.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	networkcmp
SHLIB_MAJOR=	1
MAN=	libnetworkcmp.3 network_state.3
MLINKS+=network_state.3 network_state_open.3
MLINKS+=network_state.3 network_state_watch.3
MLINKS+=network_state.3 network_state_close.3
MLINKS+=libnetworkcmp.3 networkcmp_hello.3
MLINKS+=libnetworkcmp.3 networkcmp_connect.3
MLINKS+=libnetworkcmp.3 networkcmp_connect_ex.3
MLINKS+=libnetworkcmp.3 networkcmp_udp.3
MLINKS+=libnetworkcmp.3 networkcmp_listen.3
MLINKS+=libnetworkcmp.3 networkcmp_resolve.3
MLINKS+=libnetworkcmp.3 networkcmp_getaddrinfo.3
MLINKS+=libnetworkcmp.3 networkcmp_freeaddrinfo.3
MLINKS+=libnetworkcmp.3 networkcmp_client_open.3
MLINKS+=libnetworkcmp.3 networkcmp_client_limits.3
MLINKS+=libnetworkcmp.3 networkcmp_client_close.3
MLINKS+=libnetworkcmp.3 networkcmp_pf_open.3

SRCS=	networkcmp.c networkcmp_legacy.c network_state.c \
	${FIDLGEN_SRCS.networkcmp}
CXXSTD= c++20
WARNS?= 0
CFLAGS+= -I${FIDLGEN.networkcmp}
.include "../libfidl/runtime-includes.mk"
FILESGROUPS+= NETWORKCMP_SCHEMA
NETWORKCMP_SCHEMA= networkcmp.fidl
NETWORKCMP_SCHEMADIR= /usr/share/fidl
NETWORKCMP_SCHEMAPACKAGE= libnetworkcmp-dev
FILESGROUPS+= NETWORKCMP_NOTICE
NETWORKCMP_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
NETWORKCMP_NOTICEDIR= /usr/share/licenses/libnetworkcmp/fuchsia
INCS=	networkcmp.h networkcmp_protocol.h networkcmp_server.h \
	network_state.h network_state_protocol.h

LIBADD=	pthread service fidl_bsd cplusplus
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	networkcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	networkcmp
FIDL_SCHEMAS.networkcmp=	lib/libfidl/tests/zx.fidl \
	lib/libnetworkcmp/networkcmp.fidl
FIDL_LIBRARY.networkcmp=	bsd.network.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.lib.mk>
