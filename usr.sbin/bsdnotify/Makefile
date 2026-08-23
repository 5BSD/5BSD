.include <src.opts.mk>

PACKAGE=	bsdnotify
PROG=		bsdnotify
MAN=		bsdnotify.8
SRCS=		bsdnotify.c broker.c policy.c transport.c
LIBADD=		auditcmp channel notify pthread service ucl
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libnotify
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys

DIRS+=		NOTIFY_CAP NOTIFY_CAP_BIN NOTIFY_CAP_ETC
NOTIFY_CAP=	/Capabilities/System/BsdNotify.cap
NOTIFY_CAPPACKAGE=	bsdnotify
NOTIFY_CAP_BIN=	/Capabilities/System/BsdNotify.cap/bin
NOTIFY_CAP_BINPACKAGE=	bsdnotify
NOTIFY_CAP_ETC=	/Capabilities/System/BsdNotify.cap/etc
NOTIFY_CAP_ETCPACKAGE=	bsdnotify

BINDIR=		${NOTIFY_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/bsdnotify.ucl
SERVICESDIR=	${NOTIFY_CAP_ETC}
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

_proginstall: installdirs-NOTIFY_CAP_BIN
