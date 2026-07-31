.include <src.opts.mk>

PACKAGE=	notifycmp
PROG=		notifycmp
MAN=		notifycmp.8
SRCS=		notifycmp.c broker.c policy.c transport.c
LIBADD=		bsm channel notifycmp pthread service ucl
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libnotifycmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=		NOTIFYCMP_CAP NOTIFYCMP_CAP_BIN NOTIFYCMP_CAP_ETC
NOTIFYCMP_CAP=	/Capabilities/System/NotifyCmp.cap
NOTIFYCMP_CAPPACKAGE=	notifycmp
NOTIFYCMP_CAP_BIN=	/Capabilities/System/NotifyCmp.cap/bin
NOTIFYCMP_CAP_BINPACKAGE=	notifycmp
NOTIFYCMP_CAP_ETC=	/Capabilities/System/NotifyCmp.cap/etc
NOTIFYCMP_CAP_ETCPACKAGE=	notifycmp

BINDIR=		${NOTIFYCMP_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/notifycmp.ucl
SERVICESDIR=	${NOTIFYCMP_CAP_ETC}
SERVICESNAME_capbundle/notifycmp.ucl=	notifycmp.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		notifycmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-NOTIFYCMP_CAP_BIN
