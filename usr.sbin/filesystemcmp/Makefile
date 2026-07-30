.include <src.opts.mk>

PACKAGE=	filesystemcmp
PROG=		filesystemcmp
MAN=		filesystemcmp.8
SRCS=		filesystemcmp.c scratch.c

CFLAGS+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		bsm filesystemcmp service ucl

DIRS+=		FILESYSTEMCMP_CAP FILESYSTEMCMP_CAP_BIN FILESYSTEMCMP_CAP_ETC
FILESYSTEMCMP_CAP=	/Capabilities/System/FileSystemCmp.cap
FILESYSTEMCMP_CAPPACKAGE=	filesystemcmp
FILESYSTEMCMP_CAP_BIN=	/Capabilities/System/FileSystemCmp.cap/bin
FILESYSTEMCMP_CAP_BINPACKAGE=	filesystemcmp
FILESYSTEMCMP_CAP_ETC=	/Capabilities/System/FileSystemCmp.cap/etc
FILESYSTEMCMP_CAP_ETCPACKAGE=	filesystemcmp

BINDIR=		${FILESYSTEMCMP_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/filesystemcmp.ucl
SERVICESDIR=	${FILESYSTEMCMP_CAP_ETC}
SERVICESNAME_capbundle/filesystemcmp.ucl=	filesystemcmp.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

_proginstall: installdirs-FILESYSTEMCMP_CAP_BIN
