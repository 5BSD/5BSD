.include <src.opts.mk>

PACKAGE=	runtime
PROG=		localsysctl
PROGNAME=	Sysctl
MAN=		localsysctl.8
SRCS=		localsysctl.c config.c

CFLAGS+=	-I${SRCTOP}/lib/libsysctlcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		sysctlcmp service channel ucl
# Full binding at load so no lazy PLT work remains after cap_enter(2).
LDFLAGS+=	-Wl,-z,now

DIRS+=		SYSCTL_CAP SYSCTL_CAP_UNITS SYSCTL_CAP_UNIT \
		SYSCTL_CAP_BIN SYSCTL_CAP_CONFIG
SYSCTL_CAP=	/Capabilities/System/Sysctl.cap
SYSCTL_CAPPACKAGE=	runtime
SYSCTL_CAP_UNITS=	${SYSCTL_CAP}/Units
SYSCTL_CAP_UNIT=	${SYSCTL_CAP_UNITS}/localsysctl.unit
SYSCTL_CAP_BIN=	${SYSCTL_CAP_UNIT}/bin
SYSCTL_CAP_BINPACKAGE=	runtime
SYSCTL_CAP_CONFIG=	${SYSCTL_CAP_UNIT}/Config
SYSCTL_CAP_UNITSPACKAGE=	runtime
SYSCTL_CAP_UNITPACKAGE=	runtime
SYSCTL_CAP_CONFIGPACKAGE=	runtime

BINDIR=		${SYSCTL_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${SYSCTL_CAP}
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/localsysctl.ucl
CAP_UNITDIR=	${SYSCTL_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime

CONFS=		capbundle/sysctl.conf
CONFSDIR=	${SYSCTL_CAP_CONFIG}
CONFSNAME_capbundle/sysctl.conf=	sysctl.conf
CONFSPACKAGE=	runtime

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

_proginstall: installdirs-SYSCTL_CAP_BIN
