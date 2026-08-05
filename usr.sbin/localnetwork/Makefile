.include <src.opts.mk>

PACKAGE=	localnetwork
PROG=		localnetwork
MAN=		localnetwork.8
SRCS=		io.c networkcmp.c policy.c session.c

CFLAGS+=	-DWITH_CASPER
CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		auditcmp cap_net casper channel networkcmp pthread service

DIRS+=		NETWORKCMP_CAP NETWORKCMP_CAP_BIN NETWORKCMP_CAP_ETC
NETWORKCMP_CAP=	/Capabilities/System/LocalNetwork.cap
NETWORKCMP_CAPPACKAGE=	localnetwork
NETWORKCMP_CAP_BIN=	/Capabilities/System/LocalNetwork.cap/bin
NETWORKCMP_CAP_BINPACKAGE=	localnetwork
NETWORKCMP_CAP_ETC=	/Capabilities/System/LocalNetwork.cap/etc
NETWORKCMP_CAP_ETCPACKAGE=	localnetwork

BINDIR=		${NETWORKCMP_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/localnetwork.ucl
SERVICESDIR=	${NETWORKCMP_CAP_ETC}
SERVICESNAME_capbundle/localnetwork.ucl=	localnetwork.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		localnetwork_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-NETWORKCMP_CAP_BIN
