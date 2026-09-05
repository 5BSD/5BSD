.include <src.opts.mk>

PACKAGE=	runtime
PROG=		waspnest
MAN=		waspnest.8

SRCS=		waspnest.c

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

# waspnest is a serviced-supervised unit: it ships as the Waspnest.cap capability
# bundle (exposing system.Waspnest, the VM capability) and serviced launches it
# on demand, rather than living at /usr/sbin and being spawned by PID 1.  The
# binary is the unit's program.  bhyve remains the underlying hypervisor engine.
DIRS+=		WN_CAP WN_CAP_UNITS WN_CAP_UNIT WN_CAP_BIN
WN_CAP=		/Capabilities/System/Waspnest.cap
WN_CAPPACKAGE=	runtime
WN_CAP_UNITS=	${WN_CAP}/Units
WN_CAP_UNITSPACKAGE=	runtime
WN_CAP_UNIT=	${WN_CAP_UNITS}/waspnest.unit
WN_CAP_UNITPACKAGE=	runtime
WN_CAP_BIN=	${WN_CAP_UNIT}/bin
WN_CAP_BINPACKAGE=	runtime

BINDIR=		${WN_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${WN_CAP}
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/waspnest.ucl
CAP_UNITDIR=	${WN_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime

# vmd_proto.h (libauthorityrt), AF_VSOCK/sockaddr_vm (sys/sys/vsock.h), and the
# socket-free service_provider transport (libservice over libchannel).
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys

LIBADD=		service channel

.include <bsd.prog.mk>

_proginstall: installdirs-WN_CAP_BIN
