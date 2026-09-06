.include <src.opts.mk>

PACKAGE=	bsdnotify
PROG=		bsdnotify
PROGNAME=	Notify
MAN=		bsdnotify.8
SRCS=		bsdnotify.c broker.c policy.c transport.c
LIBADD=		auditcmp channel notify pthread service ucl logcmp
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libnotify
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=		NOTIFY_CAP NOTIFY_CAP_UNITS NOTIFY_CAP_UNIT NOTIFY_CAP_BIN \
		NOTIFY_CAP_CONFIG
NOTIFY_CAP=	/Capabilities/System/Notify.cap
NOTIFY_CAPPACKAGE=	bsdnotify
NOTIFY_CAP_UNITS=	${NOTIFY_CAP}/Units
NOTIFY_CAP_UNIT=	${NOTIFY_CAP_UNITS}/bsdnotify.unit
NOTIFY_CAP_BIN=	${NOTIFY_CAP_UNIT}/bin
NOTIFY_CAP_BINPACKAGE=	bsdnotify
NOTIFY_CAP_CONFIG=	${NOTIFY_CAP_UNIT}/Config
NOTIFY_CAP_UNITSPACKAGE=	bsdnotify
NOTIFY_CAP_UNITPACKAGE=	bsdnotify
NOTIFY_CAP_CONFIGPACKAGE=	bsdnotify

BINDIR=		${NOTIFY_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${NOTIFY_CAP}
CAP_BUNDLEMODE=	0444
CAP_UNIT=	capbundle/bsdnotify.ucl
CAP_UNITDIR=	${NOTIFY_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444

CONFS=		capbundle/bsdnotify.conf
CONFSDIR=	${NOTIFY_CAP_CONFIG}
CONFSNAME_capbundle/bsdnotify.conf=	bsdnotify.conf
CONFSPACKAGE=	bsdnotify

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		bsdnotify_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-NOTIFY_CAP_BIN
