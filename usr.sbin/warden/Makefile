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

LIBADD=		service channel jail md

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

_proginstall: installdirs-NS_CAP_BIN
