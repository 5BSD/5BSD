.include <src.opts.mk>

PACKAGE=	logcmp
PROG=		logcmp
MAN=		logcmp.8
SRCS=		logcmp.c session.c

CFLAGS+=	-DWITH_CASPER
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		bsm cap_syslog casper channel logcmp service shmring

DIRS+=		LOGCMP_CAP LOGCMP_CAP_BIN LOGCMP_CAP_ETC
LOGCMP_CAP=	/Capabilities/System/LogCmp.cap
LOGCMP_CAPPACKAGE=	logcmp
LOGCMP_CAP_BIN=	/Capabilities/System/LogCmp.cap/bin
LOGCMP_CAP_BINPACKAGE=	logcmp
LOGCMP_CAP_ETC=	/Capabilities/System/LogCmp.cap/etc
LOGCMP_CAP_ETCPACKAGE=	logcmp

BINDIR=		${LOGCMP_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/logcmp.ucl
SERVICESDIR=	${LOGCMP_CAP_ETC}
SERVICESNAME_capbundle/logcmp.ucl=	logcmp.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		logcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-LOGCMP_CAP_BIN
