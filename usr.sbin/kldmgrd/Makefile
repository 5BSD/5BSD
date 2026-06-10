.include <src.opts.mk>

PACKAGE=kldmgrd
PROG=	kldmgrd
MAN=	kldmgrd.8
SRCS=	kldmgrd_main.c

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapability
LIBADD=		capability service

BINDIR=	/Capabilities/System/Kldmgr.cap/bin

FILESGROUPS=	SERVICES
SERVICES=	capbundle/kldmgrd.ucl
SERVICESDIR=	/Capabilities/System/Kldmgr.cap/etc
SERVICESNAME_capbundle/kldmgrd.ucl=	kldmgrd.ucl

beforeinstall:
	${INSTALL} -d -m 0755 ${DESTDIR}${BINDIR}
	${INSTALL} -d -m 0755 ${DESTDIR}${SERVICESDIR}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>
