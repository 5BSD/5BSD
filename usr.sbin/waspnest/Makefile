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

# pthread: the parent runs the reclaim handler on libservice's control-dispatch
# thread and a periodic reconciliation timer thread, both serialized against the
# accept loop by a mutex around the window registry (capability-cleanup, see
# docs/capability-lifecycle-cleanup.md).
LIBADD=		service channel pthread

# Optional USDT DTrace provider (waspnest_provider.d -> waspnest_provider.h).
# MK_DTRACE-guarded so waspnest builds identically with and without DTrace; the
# probe shims in waspnest_probes.h no-op when WITH_DTRACE is undefined.
.if ${MK_DTRACE} != "no"
SRCS+=		waspnest_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-WN_CAP_BIN
