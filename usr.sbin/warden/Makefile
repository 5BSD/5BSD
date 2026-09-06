.include <src.opts.mk>

PACKAGE=	runtime
PROG=		warden
MAN=		warden.8

SRCS=		warden.c

# warden is a serviced-supervised unit (docs/authorityd-serviced-layering-
# cleanup.md, Phase 3): it ships as the Namespace.cap capability bundle and
# serviced launches it, rather than living at /usr/sbin and being spawned by
# PID 1.  The binary is the unit's program.
DIRS+=		NS_CAP NS_CAP_UNITS NS_CAP_UNIT NS_CAP_BIN
NS_CAP=		/Capabilities/System/Namespace.cap
NS_CAPPACKAGE=	runtime
NS_CAP_UNITS=	${NS_CAP}/Units
NS_CAP_UNITSPACKAGE=	runtime
NS_CAP_UNIT=	${NS_CAP_UNITS}/warden.unit
NS_CAP_UNITPACKAGE=	runtime
NS_CAP_BIN=	${NS_CAP_UNIT}/bin
NS_CAP_BINPACKAGE=	runtime

BINDIR=		${NS_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${NS_CAP}
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/warden.ucl
CAP_UNITDIR=	${NS_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime

# warden_proto.h (libauthorityrt), jail_set/jail_getv (libjail), and the
# socket-free service_provider transport (libservice over libchannel).
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys

# pthread: the parent runs the reclaim handler on libservice's control-dispatch
# thread and a jittered periodic reconciliation sweep on its own timer thread.
LIBADD=		service channel jail md pthread

# Optional USDT DTrace provider (warden_provider.d -> warden_provider.h).
# MK_DTRACE-guarded so warden builds identically with and without DTrace; the
# probe shims in warden_probes.h no-op when WITH_DTRACE is undefined.
.if ${MK_DTRACE} != "no"
SRCS+=		warden_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

_proginstall: installdirs-NS_CAP_BIN
