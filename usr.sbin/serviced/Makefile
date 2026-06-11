.include <src.opts.mk>

PACKAGE=serviced
PROG=	serviced
BINDIR=	/usr/libexec
MAN=	serviced.8
SRCS=	serviced.c bundle_registry.c caprt_direct.c depgraph.c execute.c \
	kldmgr_client.c naming.c on_demand.c oracle_client.c \
	reload.c sctl.c startup.c svc_proto.c supervisor.c
HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

DIRS+=	CAPABILITIES CAPABILITIES_SYSTEM
CAPABILITIES=	/Capabilities
CAPABILITIESPACKAGE=	serviced
CAPABILITIES_SYSTEM=	/Capabilities/System
CAPABILITIES_SYSTEMPACKAGE=	serviced

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/liboraclert
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capbundle oraclert jail ucl util

.if ${MK_DTRACE} != "no"
SRCS+=		serviced_provider.d
CFLAGS+=	-I${.OBJDIR}
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.prog.mk>
