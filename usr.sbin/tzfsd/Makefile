.include <src.opts.mk>

PACKAGE=	runtime
PROG=		tzfsd
MAN=		tzfsd.8 tzfs.conf.5

SRCS=		tzfsd.c config.c layout.c request.c

# tzfsd_proto.h (liboraclert), tzfs_* verbs (libtrustedzfs), sys/zfshandle.h,
# and the UCL config parser.
CFLAGS+=	-I${SRCTOP}/lib/liboraclert
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

LIBADD=		trustedzfs ucl

.include <bsd.prog.mk>
