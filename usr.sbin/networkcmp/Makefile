.include <src.opts.mk>

PACKAGE=	networkcmp
PROG=		networkcmp
MAN=		networkcmp.8
SRCS=		io.c networkcmp.c policy.c session.c

CFLAGS+=	-DWITH_CASPER
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		bsm cap_net casper channel networkcmp service

DIRS+=		NETWORKCMP_CAP NETWORKCMP_CAP_BIN NETWORKCMP_CAP_ETC
NETWORKCMP_CAP=	/Capabilities/System/NetworkCmp.cap
NETWORKCMP_CAPPACKAGE=	networkcmp
NETWORKCMP_CAP_BIN=	/Capabilities/System/NetworkCmp.cap/bin
NETWORKCMP_CAP_BINPACKAGE=	networkcmp
NETWORKCMP_CAP_ETC=	/Capabilities/System/NetworkCmp.cap/etc
NETWORKCMP_CAP_ETCPACKAGE=	networkcmp

BINDIR=		${NETWORKCMP_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/networkcmp.ucl
SERVICESDIR=	${NETWORKCMP_CAP_ETC}
SERVICESNAME_capbundle/networkcmp.ucl=	networkcmp.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		networkcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-NETWORKCMP_CAP_BIN
