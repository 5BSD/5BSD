.include <src.opts.mk>

PACKAGE=	runtime
PROG=		tzfsd
MAN=		tzfsd.8 tzfs.conf.5

SRCS=		tzfsd.c config.c layout.c nvwalk.c request.c

# Flavor artifact producer (admin/build tool).
SCRIPTS=	tzfs-mkflavor.sh
SCRIPTSNAME_tzfs-mkflavor.sh=	tzfs-mkflavor

# Default configuration under /etc/capability.
CONFS=		tzfsd.ucl
CONFSDIR=	/etc/capability

# Directory that holds baked flavor send-stream artifacts.
DIRS+=		TZFSSHARE
TZFSSHARE=	/usr/share/tzfs

# tzfsd_proto.h (libauthorityrt), tzfs_* verbs (libtrustedzfs), sys/zfshandle.h,
# and the UCL config parser.
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

LIBADD=		trustedzfs ucl nvpair

.include <bsd.prog.mk>
