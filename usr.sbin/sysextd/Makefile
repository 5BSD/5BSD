.include <src.opts.mk>

PACKAGE=	runtime
PROG=		sysextd
MAN=		sysextd.8

SRCS=		sysextd.c

# The kernel-module allow-list (default-deny) config, installed under
# /Capabilities/Config; a missing file leaves sysextd's built-in allow-list.
CONFS=		sysextd.ucl
CONFSDIR=	/Capabilities/Config

# sysextd is a serviced-supervised unit (docs/capability-authority-model.md): it
# ships as the SystemExtension.cap capability bundle and serviced launches it,
# rather than living at /usr/sbin and being spawned by PID 1.  The binary is the
# unit's program.
DIRS+=		SYSEXT_CAP SYSEXT_CAP_UNITS SYSEXT_CAP_UNIT SYSEXT_CAP_BIN
SYSEXT_CAP=	/Capabilities/System/SystemExtension.cap
SYSEXT_CAPPACKAGE=	runtime
SYSEXT_CAP_UNITS=	${SYSEXT_CAP}/Units
SYSEXT_CAP_UNITSPACKAGE=	runtime
SYSEXT_CAP_UNIT=	${SYSEXT_CAP_UNITS}/sysextd.unit
SYSEXT_CAP_UNITPACKAGE=	runtime
SYSEXT_CAP_BIN=	${SYSEXT_CAP_UNIT}/bin
SYSEXT_CAP_BINPACKAGE=	runtime

BINDIR=		${SYSEXT_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${SYSEXT_CAP}
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/sysextd.ucl
CAP_UNITDIR=	${SYSEXT_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime

# sysext_proto.h (libauthorityrt) and the socket-free service_provider transport
# (libservice over libchannel).  sysextd holds no /dev/mac_capability handle: its
# kldload authority arrives as a serviced-delivered system token, authorized by
# service_provider_authorize_capabilities(3).
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

LIBADD=		service channel ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

# Optional USDT DTrace provider (sysextd_provider.d -> sysextd_provider.h).
# MK_DTRACE-guarded so sysextd builds identically with and without DTrace; the
# probe shims in sysextd_probes.h no-op when WITH_DTRACE is undefined.
.if ${MK_DTRACE} != "no"
SRCS+=		sysextd_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-SYSEXT_CAP_BIN
