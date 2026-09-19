.include <src.opts.mk>

PACKAGE=	runtime
PROG=	BSDPower
MAN=	BSDPower.8
SRCS=	BSDPower.c config.c

CFLAGS+=	-I${SRCTOP}/lib/libpowercmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		powercmp service channel ucl
# Full binding at load so no lazy PLT work remains after startup.
LDFLAGS+=	-Wl,-z,now

DIRS+=		POWER_CAP POWER_CAP_UNITS POWER_CAP_UNIT \
		POWER_CAP_BIN POWER_CAP_CONFIG
POWER_CAP=	/Capabilities/System/Power.cap
POWER_CAPPACKAGE=	runtime
POWER_CAP_UNITS=	${POWER_CAP}/Units
POWER_CAP_UNIT=	${POWER_CAP_UNITS}/bsdpower.unit
POWER_CAP_BIN=	${POWER_CAP_UNIT}/bin
POWER_CAP_BINPACKAGE=	runtime
POWER_CAP_CONFIG=	${POWER_CAP_UNIT}/Config
POWER_CAP_UNITSPACKAGE=	runtime
POWER_CAP_UNITPACKAGE=	runtime
POWER_CAP_CONFIGPACKAGE=	runtime

BINDIR=		${POWER_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT CAP_CONFIG
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${POWER_CAP}
CAP_BUNDLENAME=	Bundle.ucl
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/BSDPower.ucl
CAP_UNITDIR=	${POWER_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime
CAP_CONFIG=	capbundle/power.conf
CAP_CONFIGDIR=	${POWER_CAP_CONFIG}
CAP_CONFIGNAME=	power.conf
CAP_CONFIGMODE=	0444
CAP_CONFIGPACKAGE=	runtime

# Optional USDT DTrace provider (BSDPower_provider.d -> BSDPower_provider.h).
# MK_DTRACE-guarded; the probe shims in BSDPower_probes.h no-op without it.
.if ${MK_DTRACE} != "no"
SRCS+=		BSDPower_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

_proginstall: installdirs-POWER_CAP_BIN
