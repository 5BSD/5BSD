.include <src.opts.mk>

PACKAGE=kldmgrd
PROG=	kldmgrd
MAN=	kldmgrd.8
SRCS=	kldmgrd_main.c

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
LIBADD=		bsm channel service

DIRS+=	KLDMGR_CAP KLDMGR_CAP_BIN KLDMGR_CAP_ETC
KLDMGR_CAP=	/Capabilities/System/Kldmgr.cap
KLDMGR_CAPPACKAGE=	kldmgrd
KLDMGR_CAP_BIN=	/Capabilities/System/Kldmgr.cap/bin
KLDMGR_CAP_BINPACKAGE=	kldmgrd
KLDMGR_CAP_ETC=	/Capabilities/System/Kldmgr.cap/etc
KLDMGR_CAP_ETCPACKAGE=	kldmgrd

BINDIR=	${KLDMGR_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/kldmgrd.ucl
SERVICESDIR=	${KLDMGR_CAP_ETC}
SERVICESNAME_capbundle/kldmgrd.ucl=	kldmgrd.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		kldmgrd_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-KLDMGR_CAP_BIN
