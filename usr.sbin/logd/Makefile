.include <src.opts.mk>

PACKAGE=	logd
PROG=		logd
PROGNAME=	Log
MAN=		logd.8
SRCS=		logcmp.c session.c config.c store.c storage.c

CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		auditcmp channel logcmp md pthread service shmring ucl

DIRS+=		LOGCMP_CAP LOGCMP_CAP_UNITS LOGCMP_CAP_UNIT LOGCMP_CAP_BIN \
		LOGCMP_CAP_CONFIG
LOGCMP_CAP=	/Capabilities/System/Log.cap
LOGCMP_CAPPACKAGE=	logd
LOGCMP_CAP_UNITS=	${LOGCMP_CAP}/Units
LOGCMP_CAP_UNIT=	${LOGCMP_CAP_UNITS}/logd.unit
LOGCMP_CAP_BIN=	${LOGCMP_CAP_UNIT}/bin
LOGCMP_CAP_BINPACKAGE=	logd
LOGCMP_CAP_CONFIG=	${LOGCMP_CAP_UNIT}/Config
LOGCMP_CAP_UNITSPACKAGE=	logd
LOGCMP_CAP_UNITPACKAGE=	logd
LOGCMP_CAP_CONFIGPACKAGE=	logd
BINDIR=		${LOGCMP_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${LOGCMP_CAP}
CAP_BUNDLEMODE=	0444
CAP_UNIT=	capbundle/logd.ucl
CAP_UNITDIR=	${LOGCMP_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444

CONFS=		capbundle/logd.conf
CONFSDIR=	${LOGCMP_CAP_CONFIG}
CONFSNAME_capbundle/logd.conf=	logd.conf
CONFSPACKAGE=	logd

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		logd_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-LOGCMP_CAP_BIN
