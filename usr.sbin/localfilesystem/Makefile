.include <src.opts.mk>

PACKAGE=	localfilesystem
PROG=		localfilesystem
PROGNAME=	Filesystem
MAN=		localfilesystem.8
SRCS=		disk.c filesystemcmp.c scratch.c store.c

CFLAGS+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
LIBADD=		auditcmp channel filesystemcmp service

DIRS+=		FILESYSTEMCMP_CAP FILESYSTEMCMP_CAP_UNITS \
		FILESYSTEMCMP_CAP_UNIT FILESYSTEMCMP_CAP_BIN
FILESYSTEMCMP_CAP=	/Capabilities/System/Filesystem.cap
FILESYSTEMCMP_CAPPACKAGE=	localfilesystem
FILESYSTEMCMP_CAP_UNITS=	${FILESYSTEMCMP_CAP}/Units
FILESYSTEMCMP_CAP_UNIT=	${FILESYSTEMCMP_CAP_UNITS}/localfilesystem.unit
FILESYSTEMCMP_CAP_BIN=	${FILESYSTEMCMP_CAP_UNIT}/bin
FILESYSTEMCMP_CAP_BINPACKAGE=	localfilesystem
FILESYSTEMCMP_CAP_UNITSPACKAGE=	localfilesystem
FILESYSTEMCMP_CAP_UNITPACKAGE=	localfilesystem

BINDIR=		${FILESYSTEMCMP_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${FILESYSTEMCMP_CAP}
CAP_BUNDLEMODE=	0444
CAP_UNIT=	capbundle/localfilesystem.ucl
CAP_UNITDIR=	${FILESYSTEMCMP_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=		localfilesystem_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.prog.mk>

_proginstall: installdirs-FILESYSTEMCMP_CAP_BIN
