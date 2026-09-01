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
DIRS+=		STORAGE_CAP STORAGE_CAP_UNITS STORAGE_CAP_UNIT STORAGE_CAP_BIN \
		STORAGE_CAP_CONFIG
STORAGE_CAP=	/Capabilities/System/Storage.cap
STORAGE_CAPPACKAGE=	runtime
STORAGE_CAP_UNITS=	${STORAGE_CAP}/Units
STORAGE_CAP_UNITSPACKAGE=	runtime
STORAGE_CAP_UNIT=	${STORAGE_CAP_UNITS}/tzfsd.unit
STORAGE_CAP_UNITPACKAGE=	runtime
STORAGE_CAP_BIN=	${STORAGE_CAP_UNIT}/bin
STORAGE_CAP_BINPACKAGE=	runtime
STORAGE_CAP_CONFIG=	${STORAGE_CAP_UNIT}/Config
STORAGE_CAP_CONFIGPACKAGE=	runtime

BINDIR=		${STORAGE_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${STORAGE_CAP}
CAP_BUNDLEMODE=	0444
CAP_BUNDLEPACKAGE=	runtime
CAP_UNIT=	capbundle/tzfsd.ucl
CAP_UNITDIR=	${STORAGE_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444
CAP_UNITPACKAGE=	runtime

# tzfsd_proto.h (libauthorityrt), tzfs_* verbs (libtrustedzfs), sys/zfshandle.h,
# and the UCL config parser.
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

LIBADD=		trustedzfs ucl nvpair

.include <bsd.prog.mk>

_proginstall: installdirs-STORAGE_CAP_BIN
