.include <src.opts.mk>

PACKAGE=	runtime
PROG=	BSDTime
MAN=	BSDTime.8
SRCS=	BSDTime.c config.c

CFLAGS+=	-I${SRCTOP}/lib/libtimecmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		timecmp service channel ucl
# Full binding at load so no lazy PLT work remains after startup.
LDFLAGS+=	-Wl,-z,now

DIRS+=		TIME_CAP TIME_CAP_UNITS TIME_CAP_UNIT \
		TIME_CAP_BIN TIME_CAP_CONFIG
TIME_CAP=	/Capabilities/System/Time.cap
TIME_CAPPACKAGE=	runtime
TIME_CAP_UNITS=	${TIME_CAP}/Units
TIME_CAP_UNIT=	${TIME_CAP_UNITS}/bsdtime.unit
TIME_CAP_BIN=	${TIME_CAP_UNIT}/bin
TIME_CAP_BINPACKAGE=	runtime
TIME_CAP_CONFIG=	${TIME_CAP_UNIT}/Config
TIME_CAP_UNITSPACKAGE=	runtime
TIME_CAP_UNITPACKAGE=	runtime
TIME_CAP_CONFIGPACKAGE=	runtime

BINDIR=		${TIME_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT CAP_CONFIG
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${TIME_CAP}
CAP_BUNDLENAME=	Bundle.ucl
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/BSDTime.ucl
CAP_UNITDIR=	${TIME_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime
CAP_CONFIG=	capbundle/time.conf
CAP_CONFIGDIR=	${TIME_CAP_CONFIG}
CAP_CONFIGNAME=	time.conf
CAP_CONFIGMODE=	0444
CAP_CONFIGPACKAGE=	runtime

# Optional USDT DTrace provider (BSDTime_provider.d -> BSDTime_provider.h).
# MK_DTRACE-guarded; the probe shims in BSDTime_probes.h no-op without it.
.if ${MK_DTRACE} != "no"
SRCS+=		BSDTime_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

_proginstall: installdirs-TIME_CAP_BIN
