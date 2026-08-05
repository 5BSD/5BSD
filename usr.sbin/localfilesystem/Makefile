.include <src.opts.mk>

PACKAGE=	localfilesystem
PROG=		localfilesystem
MAN=		localfilesystem.8
SRCS=		disk.c filesystemcmp.c scratch.c store.c

CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		auditcmp channel filesystemcmp service

DIRS+=		FILESYSTEMCMP_CAP FILESYSTEMCMP_CAP_BIN FILESYSTEMCMP_CAP_ETC
FILESYSTEMCMP_CAP=	/Capabilities/System/LocalFilesystem.cap
FILESYSTEMCMP_CAPPACKAGE=	localfilesystem
FILESYSTEMCMP_CAP_BIN=	/Capabilities/System/LocalFilesystem.cap/bin
FILESYSTEMCMP_CAP_BINPACKAGE=	localfilesystem
FILESYSTEMCMP_CAP_ETC=	/Capabilities/System/LocalFilesystem.cap/etc
FILESYSTEMCMP_CAP_ETCPACKAGE=	localfilesystem

BINDIR=		${FILESYSTEMCMP_CAP_BIN}

FILESGROUPS=	SERVICES
SERVICES=	capbundle/localfilesystem.ucl
SERVICESDIR=	${FILESYSTEMCMP_CAP_ETC}
SERVICESNAME_capbundle/localfilesystem.ucl=	localfilesystem.ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		localfilesystem_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-FILESYSTEMCMP_CAP_BIN
