.include <src.opts.mk>

PACKAGE=switchboard
PROG=	switchboard
BINDIR=	/usr/libexec
MAN=	switchboard.5 switchboard.8
SRCS=	switchboard.c activation.c anoint.c activation_calendar.c bundle_registry.c bundle_selection.c domain.c mac_capability_direct.c execute.c \
	lifecycle.c installation_query.c fd_budget.c management.c manifest_compare.c \
	naming.c on_demand.c capsule_client.c rc_adopt.c \
	rc_ingest.c reclaim_bridge.c \
	reload.c sctl.c switchboard_audit.c startup.c svc_proto.c supervisor.c
HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

DIRS+=	CAPABILITIES CAPABILITIES_SYSTEM
CAPABILITIES=	/Capabilities
CAPABILITIESPACKAGE=	switchboard
CAPABILITIES_SYSTEM=	/Capabilities/System
CAPABILITIES_SYSTEMPACKAGE=	switchboard

DIRS+= CAPABILITIES_CONFIG SWITCHBOARD_CONFIG SWITCHBOARD_LIFECYCLE
CAPABILITIES_CONFIG= /Capabilities/Config
SWITCHBOARD_CONFIG= /Capabilities/Config/switchboard
SWITCHBOARD_LIFECYCLE= /Capabilities/Config/switchboard/lifecycle
SWITCHBOARD_LIFECYCLEOWN= capability
SWITCHBOARD_LIFECYCLEGROUP= capability
SWITCHBOARD_LIFECYCLEMODE= 0700

FILESGROUPS+=	CMP_EXAMPLES
CMP_EXAMPLES=	examples/timer-activation.ucl \
		examples/path-activation.ucl \
		examples/socket-activation.ucl
CMP_EXAMPLESDIR=	${SHAREDIR}/examples/switchboard
CMP_EXAMPLESPACKAGE=	switchboard

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/libcapability
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		capability capbundle channel capsulert service ucl util bsm

# Emit OpenBSM audit records for security-relevant events (control-socket
# privileged commands, service exec under changed credentials, capability
# minting, configuration reload).  See switchboard_audit.c.
CFLAGS+=	-DUSE_BSM_AUDIT

.if ${MK_DTRACE} != "no"
SRCS+=		switchboard_provider.d
CFLAGS+=	-I${.OBJDIR}
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.prog.mk>
