SHLIBDIR?=	/lib

.include <src.opts.mk>

PACKAGE=	runtime
LIB=		tzfsd
SHLIB_MAJOR=	1

SRCS=		tzfsd.c
INCS=		tzfsd.h
MAN=		libtzfsd.3

MLINKS+=	libtzfsd.3 tzfsd_connect.3 \
		libtzfsd.3 tzfsd_request.3 \
		libtzfsd.3 tzfsd_release.3 \
		libtzfsd.3 tzfsd_ping.3 \
		libtzfsd.3 tzfsd_mount_dir.3

# tzfsd_proto.h lives with the other capability protocols in libauthorityrt;
# trustedzfs.h provides tzfs_mount() for tzfsd_mount_dir(); libservice provides
# the socket-free channel client (service_open/service_session_call).
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys		# sys/zfshandle.h (via trustedzfs.h)
LIBADD=		trustedzfs service channel

.include <bsd.lib.mk>
