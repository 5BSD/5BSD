.include <src.opts.mk>

PACKAGE=	runtime
PROG=		tzfsd
MAN=		tzfsd.8 tzfs.conf.5

SRCS=		tzfsd.c config.c layout.c nvwalk.c request.c

# Default configuration under /Capabilities/Config.
CONFS=		tzfsd.ucl
CONFSDIR=	/Capabilities/Config

DIRS+=		TZFSSHARE
TZFSSHARE=	/usr/share/tzfs

# tzfsd is a serviced-supervised unit (docs/capability-authority-model.md, P4a):
# it ships as the Storage.cap capability bundle and serviced launches it, rather
# than living at /usr/sbin and being spawned by PID 1.  The tzfsd binary is the
# unit's program; the runtime storage it manages (persistent/ephemeral datasets)
# is provisioned separately at runtime, so this static bundle carries no
# circularity.
DIRS+=		FS_CAP FS_CAP_UNITS FS_CAP_UNIT FS_CAP_BIN \
		FS_CAP_CONFIG
FS_CAP=	/Capabilities/System/Filesystem.cap
FS_CAPPACKAGE=	runtime
FS_CAP_UNITS=	${FS_CAP}/Units
FS_CAP_UNITSPACKAGE=	runtime
FS_CAP_UNIT=	${FS_CAP_UNITS}/tzfsd.unit
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
CAP_UNIT=	capbundle/tzfsd.ucl
CAP_UNITDIR=	${FS_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime

# tzfsd_proto.h (libauthorityrt), tzfs_* verbs (libtrustedzfs), sys/zfshandle.h,
# the UCL config parser, and the socket-free service_provider transport
# (libservice over libchannel).
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

LIBADD=		trustedzfs ucl nvpair service channel md

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>

_proginstall: installdirs-FS_CAP_BIN
