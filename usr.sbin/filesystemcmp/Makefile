.include <src.opts.mk>

PACKAGE=	filesystemcmp
PROG=		filesystemcmp
MAN=		filesystemcmp.8
SRCS=		disk.c filesystemcmp.c scratch.c store.c

CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		bsm channel filesystemcmp service

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

.if ${MK_DTRACE} != "no"
SRCS+=		filesystemcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-FILESYSTEMCMP_CAP_BIN
