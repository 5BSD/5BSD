.include <src.opts.mk>

PACKAGE=rebootd
PROG=	rebootd
MAN=	rebootd.8
SRCS=	rebootd_main.c

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapability
LIBADD=		capability service

BINDIR=	/Capabilities/System/Reboot.cap/bin

FILESGROUPS=	SERVICES
SERVICES=	capbundle/rebootd.ucl
SERVICESDIR=	/Capabilities/System/Reboot.cap/etc
SERVICESNAME_capbundle/rebootd.ucl=	rebootd.ucl

beforeinstall:
	${INSTALL} -d -m 0755 ${DESTDIR}${BINDIR}
	${INSTALL} -d -m 0755 ${DESTDIR}${SERVICESDIR}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>
