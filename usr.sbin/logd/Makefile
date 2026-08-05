.include <src.opts.mk>

PACKAGE=	logd
PROG=		logd
MAN=		logd.8
SRCS=		logcmp.c session.c config.c store.c storage.c

CFLAGS+=	-DWITH_CASPER
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		auditcmp cap_syslog casper channel logcmp md pthread service shmring ucl

DIRS+=		LOGCMP_CAP LOGCMP_CAP_BIN LOGCMP_CAP_ETC
DIRS+=		LOGCMP_DBDIR
LOGCMP_CAP=	/Capabilities/System/Log.cap
LOGCMP_CAPPACKAGE=	logd
LOGCMP_CAP_BIN=	/Capabilities/System/Log.cap/bin
LOGCMP_CAP_BINPACKAGE=	logd
LOGCMP_CAP_ETC=	/Capabilities/System/Log.cap/etc
LOGCMP_CAP_ETCPACKAGE=	logd
LOGCMP_DBDIR=	/var/db/logd
LOGCMP_DBDIRPACKAGE=	logd
LOGCMP_DBDIR_MODE=	0700
LOGCMP_DBDIR_OWN=	capability
LOGCMP_DBDIR_GRP=	capability

BINDIR=		${LOGCMP_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/logd.ucl
SERVICESDIR=	${LOGCMP_CAP_ETC}
SERVICESNAME_capbundle/logd.ucl=	logd.ucl

CONFS=		capbundle/logd.conf
CONFSDIR=	/etc
CONFSNAME_capbundle/logd.conf=	logd.conf

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		logd_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-LOGCMP_CAP_BIN
