.include <src.opts.mk>

PACKAGE=	bsdnotify
PROG=		bsdnotify
MAN=		bsdnotify.8
SRCS=		notifycmp.c broker.c policy.c transport.c
LIBADD=		auditcmp channel notifycmp pthread service ucl
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libnotifycmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=		NOTIFYCMP_CAP NOTIFYCMP_CAP_BIN NOTIFYCMP_CAP_ETC
NOTIFYCMP_CAP=	/Capabilities/System/BsdNotify.cap
NOTIFYCMP_CAPPACKAGE=	bsdnotify
NOTIFYCMP_CAP_BIN=	/Capabilities/System/BsdNotify.cap/bin
NOTIFYCMP_CAP_BINPACKAGE=	bsdnotify
NOTIFYCMP_CAP_ETC=	/Capabilities/System/BsdNotify.cap/etc
NOTIFYCMP_CAP_ETCPACKAGE=	bsdnotify

BINDIR=		${NOTIFYCMP_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/bsdnotify.ucl
SERVICESDIR=	${NOTIFYCMP_CAP_ETC}
SERVICESNAME_capbundle/bsdnotify.ucl=	bsdnotify.ucl

CONFS=		capbundle/bsdnotify.conf
CONFSDIR=	/etc
CONFSNAME_capbundle/bsdnotify.conf=	bsdnotify.conf

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		bsdnotify_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-NOTIFYCMP_CAP_BIN
