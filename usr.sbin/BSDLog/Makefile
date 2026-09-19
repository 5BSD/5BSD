.include <src.opts.mk>

PACKAGE=	bsdlog
PROG=	BSDLog
MAN=		BSDLog.8
SRCS=		logcmp.c session.c config.c store.c storage.c

CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		auditcmp capreclaim channel logcmp md pthread service shmring ucl

DIRS+=		LOGCMP_CAP LOGCMP_CAP_UNITS LOGCMP_CAP_UNIT LOGCMP_CAP_BIN \
		LOGCMP_CAP_CONFIG
LOGCMP_CAP=	/Capabilities/System/Log.cap
LOGCMP_CAPPACKAGE=	bsdlog
LOGCMP_CAP_UNITS=	${LOGCMP_CAP}/Units
LOGCMP_CAP_UNIT=	${LOGCMP_CAP_UNITS}/bsdlog.unit
LOGCMP_CAP_BIN=	${LOGCMP_CAP_UNIT}/bin
LOGCMP_CAP_BINPACKAGE=	bsdlog
LOGCMP_CAP_CONFIG=	${LOGCMP_CAP_UNIT}/Config
LOGCMP_CAP_UNITSPACKAGE=	bsdlog
LOGCMP_CAP_UNITPACKAGE=	bsdlog
LOGCMP_CAP_CONFIGPACKAGE=	bsdlog
BINDIR=		${LOGCMP_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${LOGCMP_CAP}
CAP_BUNDLEMODE=	0444
CAP_UNIT=	capbundle/bsdlog.ucl
CAP_UNITDIR=	${LOGCMP_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444

CONFS=		capbundle/bsdlog.conf
CONFSDIR=	${LOGCMP_CAP_CONFIG}
CONFSNAME_capbundle/bsdlog.conf=	bsdlog.conf
CONFSDIRPACKAGE=	bsdlog
CONFSPACKAGE=	bsdlog

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		bsdlog_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-LOGCMP_CAP_BIN
