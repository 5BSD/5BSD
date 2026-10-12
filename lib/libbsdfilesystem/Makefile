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
# service_open(3); the bsd.filesystem.v1 client bindings come from
# libfilesystemcmp (filesystem_transact.h).
CFLAGS+=	-I${FIDLGEN.filesystemcmp} -I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/sys		# sys/zfshandle.h (via trustedzfs.h)
LIBADD=		trustedzfs service channel filesystemcmp fidl_bsd

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

# Bindings generated at build time (fidl-bindings.mk); the generated client
# code itself is linked from libfilesystemcmp.
FIDL_BINDINGS+=	filesystemcmp
FIDL_SCHEMAS.filesystemcmp=	lib/libfidl/tests/zx.fidl \
	lib/libfilesystemcmp/filesystemcmp.fidl
FIDL_LIBRARY.filesystemcmp=	bsd.filesystem.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"
.include "../libfidl/runtime-includes.mk"

.include <bsd.lib.mk>
