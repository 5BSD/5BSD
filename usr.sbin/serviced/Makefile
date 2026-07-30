.include <src.opts.mk>

PACKAGE=serviced
PROG=	serviced
BINDIR=	/usr/libexec
MAN=	serviced.8
SRCS=	serviced.c bundle_registry.c mac_capability_direct.c depgraph.c execute.c \
	kldmgr_client.c naming.c on_demand.c oracle_client.c \
	reload.c sctl.c serviced_audit.c startup.c svc_proto.c supervisor.c
HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

DIRS+=	CAPABILITIES CAPABILITIES_SYSTEM
CAPABILITIES=	/Capabilities
CAPABILITIESPACKAGE=	serviced
CAPABILITIES_SYSTEM=	/Capabilities/System
CAPABILITIES_SYSTEMPACKAGE=	serviced

FILESGROUPS+=	CMP_EXAMPLES
CMP_EXAMPLES=	examples/cmp-private.ucl \
		examples/cmp-jail.ucl \
		examples/cmp-service.ucl \
		examples/cmp-system.ucl \
		examples/component-policy.ucl
CMP_EXAMPLESDIR=	${SHAREDIR}/examples/serviced
CMP_EXAMPLESPACKAGE=	serviced

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/liboraclert
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capbundle oraclert jail ucl util bsm

# Emit OpenBSM audit records for security-relevant events (control-socket
# privileged commands, service exec under changed credentials, capability
# minting, configuration reload).  See serviced_audit.c.
CFLAGS+=	-DUSE_BSM_AUDIT

.if ${MK_DTRACE} != "no"
SRCS+=		serviced_provider.d
CFLAGS+=	-I${.OBJDIR}
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.prog.mk>
