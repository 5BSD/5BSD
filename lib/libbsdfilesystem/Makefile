SHLIBDIR?=	/lib

.include <src.opts.mk>

PACKAGE=	runtime
LIB=		bsdfilesystem
SHLIB_MAJOR=	1

SRCS=		bsdfilesystem.c
INCS=		bsdfilesystem.h
MAN=		libbsdfilesystem.3

MLINKS+=	libbsdfilesystem.3 bsdfilesystem_connect.3 \
		libbsdfilesystem.3 bsdfilesystem_adopt.3 \
		libbsdfilesystem.3 bsdfilesystem_close.3 \
		libbsdfilesystem.3 bsdfilesystem_request.3 \
		libbsdfilesystem.3 bsdfilesystem_request_quota.3 \
		libbsdfilesystem.3 bsdfilesystem_release.3 \
		libbsdfilesystem.3 bsdfilesystem_destroy.3 \
		libbsdfilesystem.3 bsdfilesystem_ping.3 \
		libbsdfilesystem.3 bsdfilesystem_begin_session.3 \
		libbsdfilesystem.3 bsdfilesystem_mount_dir.3

# bsdfilesystem_proto.h lives with the other capability protocols in libcapsulert;
# trustedzfs.h provides tzfs_mount() for bsdfilesystem_mount_dir(); libservice provides
# the socket-free channel client (service_open/service_session_call).
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys		# sys/zfshandle.h (via trustedzfs.h)
LIBADD=		trustedzfs service channel

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.lib.mk>
