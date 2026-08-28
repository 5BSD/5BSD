.include <src.opts.mk>

PACKAGE=serviced
PROG=	serviced
BINDIR=	/usr/libexec
MAN=	serviced.5 serviced.8
SRCS=	serviced.c activation.c bundle_registry.c bundle_selection.c domain.c mac_capability_direct.c execute.c \
	fd_budget.c management.c manifest_compare.c \
	storage_lifecycle.c \
	kldmgr_client.c naming.c on_demand.c authority_client.c rc_adopt.c \
	rc_ingest.c \
	reload.c sctl.c serviced_audit.c startup.c svc_proto.c supervisor.c
HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

DIRS+=	CAPABILITIES CAPABILITIES_SYSTEM
CAPABILITIES=	/Capabilities
CAPABILITIESPACKAGE=	serviced
CAPABILITIES_SYSTEM=	/Capabilities/System
CAPABILITIES_SYSTEMPACKAGE=	serviced

FILESGROUPS+=	CMP_EXAMPLES
CMP_EXAMPLES=	examples/local-descriptors.ucl \
		examples/timer-activation.ucl \
		examples/path-activation.ucl \
		examples/socket-activation.ucl
CMP_EXAMPLESDIR=	${SHAREDIR}/examples/serviced
CMP_EXAMPLESPACKAGE=	serviced

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/libcapability
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libtzfsd
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capability capbundle channel authorityrt service tzfsd jail ucl util bsm

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
