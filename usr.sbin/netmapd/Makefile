.include <src.opts.mk>

PACKAGE=	netmapd
PROG=		netmapd
MAN=		netmapd.8
SRCS=		netmapd.c netmapd_policy.c

CFLAGS+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libnetmap
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		bsm netmap service

DIRS+=		NETMAPD_CAP NETMAPD_CAP_BIN NETMAPD_CAP_ETC
NETMAPD_CAP=	/Capabilities/System/Netmapd.cap
NETMAPD_CAPPACKAGE=	netmapd
NETMAPD_CAP_BIN=	/Capabilities/System/Netmapd.cap/bin
NETMAPD_CAP_BINPACKAGE=	netmapd
NETMAPD_CAP_ETC=	/Capabilities/System/Netmapd.cap/etc
NETMAPD_CAP_ETCPACKAGE=	netmapd

BINDIR=		${NETMAPD_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/netmapd.ucl
SERVICESDIR=	${NETMAPD_CAP_ETC}
SERVICESNAME_capbundle/netmapd.ucl=	netmapd.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		netmapd_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-NETMAPD_CAP_BIN
