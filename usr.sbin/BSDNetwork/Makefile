.include <src.opts.mk>

PACKAGE=	bsdnetwork
PROG=	BSDNetwork
MAN=		BSDNetwork.8
SRCS=		networkcmp.c config.c policy.c resolver.c

# Full binding at load (no lazy PLT): everything the linker needs is resolved
# during exec, before the daemon enters capability mode, so no library work
# remains once the sandbox closes.  Pairs with bundle-local libraries resolved
# via switchboard's LD_LIBRARY_PATH_FDS delivery.
LDFLAGS+=	-Wl,-z,now
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		auditcmp channel logcmp networkcmp pthread service ucl
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp

DIRS+=		NETWORKCMP_CAP NETWORKCMP_CAP_UNITS NETWORKCMP_CAP_UNIT \
		NETWORKCMP_CAP_BIN NETWORKCMP_CAP_CONFIG
NETWORKCMP_CAP=	/Capabilities/System/Network.cap
NETWORKCMP_CAPPACKAGE=	bsdnetwork
NETWORKCMP_CAP_UNITS=	${NETWORKCMP_CAP}/Units
NETWORKCMP_CAP_UNIT=	${NETWORKCMP_CAP_UNITS}/bsdnetwork.unit
NETWORKCMP_CAP_BIN=	${NETWORKCMP_CAP_UNIT}/bin
NETWORKCMP_CAP_BINPACKAGE=	bsdnetwork
NETWORKCMP_CAP_CONFIG=	${NETWORKCMP_CAP_UNIT}/Config
NETWORKCMP_CAP_UNITSPACKAGE=	bsdnetwork
NETWORKCMP_CAP_UNITPACKAGE=	bsdnetwork
NETWORKCMP_CAP_CONFIGPACKAGE=	bsdnetwork

BINDIR=		${NETWORKCMP_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${NETWORKCMP_CAP}
CAP_BUNDLEMODE=	0444
CAP_UNIT=	capbundle/bsdnetwork.ucl
CAP_UNITDIR=	${NETWORKCMP_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444

CONFS=		capbundle/bsdnetwork.conf
CONFSDIR=	${NETWORKCMP_CAP_CONFIG}
CONFSNAME_capbundle/bsdnetwork.conf=	bsdnetwork.conf
CONFSDIRPACKAGE=	bsdnetwork
CONFSPACKAGE=	bsdnetwork

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		bsdnetwork_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-NETWORKCMP_CAP_BIN
