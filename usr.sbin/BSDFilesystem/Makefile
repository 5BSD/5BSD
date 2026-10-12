.include <src.opts.mk>

PACKAGE=	runtime
PROG=	BSDFilesystem
MAN=		BSDFilesystem.8 tzfs.conf.5

SRCS=		bsdfilesystem.c config.c layout.c nvwalk.c request.c oes_factory.c oes_session.c

# Default configuration under /Capabilities/Config.
CONFS=		bsdfilesystem.ucl
CONFSDIR=	/Capabilities/Config

DIRS+=		TZFSSHARE
TZFSSHARE=	/usr/share/tzfs

# bsdfilesystem is a switchboard-supervised unit (docs/capability-authority-model.md, P4a):
# it ships as the Storage.cap capability bundle and switchboard launches it, rather
# than living at /usr/sbin and being spawned by PID 1.  The bsdfilesystem binary is the
# unit's program; the runtime storage it manages (persistent/ephemeral datasets)
# is provisioned separately at runtime, so this static bundle carries no
# circularity.
DIRS+=		FS_CAP FS_CAP_UNITS FS_CAP_UNIT FS_CAP_BIN \
		FS_CAP_CONFIG
FS_CAP=	/Capabilities/System/Filesystem.cap
FS_CAPPACKAGE=	runtime
FS_CAP_UNITS=	${FS_CAP}/Units
FS_CAP_UNITSPACKAGE=	runtime
FS_CAP_UNIT=	${FS_CAP_UNITS}/bsdfilesystem.unit
FS_CAP_UNITPACKAGE=	runtime
FS_CAP_BIN=	${FS_CAP_UNIT}/bin
FS_CAP_BINPACKAGE=	runtime
FS_CAP_CONFIG=	${FS_CAP_UNIT}/Config
FS_CAP_CONFIGPACKAGE=	runtime

BINDIR=		${FS_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${FS_CAP}
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/bsdfilesystem.ucl
CAP_UNITDIR=	${FS_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime

# bsdfilesystem_proto.h (libcapsulert), tzfs_* verbs (libtrustedzfs), sys/zfshandle.h,
# the UCL config parser, the socket-free service_provider transport
# (libservice over libchannel), and the bsd.filesystem.v1 and bsd.oes.v1
# server bindings (their generated code is linked from libfilesystemcmp and
# liboes).
CFLAGS+=	-I${FIDLGEN.filesystemcmp} -I${FIDLGEN.oes_broker}
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/lib/libcapreclaim
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/liboes
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

LIBADD=		trustedzfs ucl nvpair service channel md capreclaim logcmp \
		filesystemcmp oes fidl_bsd

.if ${MK_DTRACE} != "no"
SRCS+=		bsdfilesystem_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CAPIMAGE_MANIFEST= ${CAP_UNIT}

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	filesystemcmp oes_broker
FIDL_SCHEMAS.filesystemcmp=	lib/libfidl/tests/zx.fidl \
	lib/libfilesystemcmp/filesystemcmp.fidl
FIDL_LIBRARY.filesystemcmp=	bsd.filesystem.v1
FIDL_SCHEMAS.oes_broker=	lib/libfidl/tests/zx.fidl \
	lib/liboes/oes_broker.fidl
FIDL_LIBRARY.oes_broker=	bsd.oes.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.prog.mk>

_proginstall: installdirs-FS_CAP_BIN
