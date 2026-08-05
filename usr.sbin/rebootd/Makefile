.include <src.opts.mk>

PACKAGE=rebootd
PROG=	rebootd
MAN=	rebootd.8
SRCS=	rebootd_main.c rebootd_ops.c rebootd_policy.c rebootd_state.c \
	rebootd_store.c

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/librebootctl
CFLAGS+=	-I${SRCTOP}/lib/libnotifycmp
CFLAGS+=	-I${SRCTOP}/lib/libfilesystemcmp
LIBADD=		bsm channel filesystemcmp notifycmp rebootctl service

DIRS+=	REBOOT_CAP REBOOT_CAP_BIN REBOOT_CAP_ETC
REBOOT_CAP=	/Capabilities/System/Reboot.cap
REBOOT_CAPPACKAGE=	rebootd
REBOOT_CAP_BIN=	/Capabilities/System/Reboot.cap/bin
REBOOT_CAP_BINPACKAGE=	rebootd
REBOOT_CAP_ETC=	/Capabilities/System/Reboot.cap/etc
REBOOT_CAP_ETCPACKAGE=	rebootd

BINDIR=	${REBOOT_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/rebootd.ucl
SERVICESDIR=	${REBOOT_CAP_ETC}
SERVICESNAME_capbundle/rebootd.ucl=	rebootd.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		rebootd_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-REBOOT_CAP_BIN
