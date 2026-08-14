SHLIBDIR?=	/lib

.include <src.opts.mk>

PACKAGE=	runtime
LIB=		trustedzfs
SHLIB_MAJOR=	1

SRCS=		trustedzfs.c
INCS=		trustedzfs.h
MAN=		trustedzfs.3

MLINKS+=	trustedzfs.3 tzfs_open.3 \
		trustedzfs.3 tzfs_derive.3 \
		trustedzfs.3 tzfs_openat.3 \
		trustedzfs.3 tzfs_info.3 \
		trustedzfs.3 tzfs_stat.3 \
		trustedzfs.3 tzfs_get_props.3 \
		trustedzfs.3 tzfs_set_prop_string.3 \
		trustedzfs.3 tzfs_set_prop_uint64.3 \
		trustedzfs.3 tzfs_snapshot.3 \
		trustedzfs.3 tzfs_snap_destroy.3 \
		trustedzfs.3 tzfs_rollback.3 \
		trustedzfs.3 tzfs_hold.3 \
		trustedzfs.3 tzfs_release.3 \
		trustedzfs.3 tzfs_create.3 \
		trustedzfs.3 tzfs_create_volume.3 \
		trustedzfs.3 tzfs_destroy.3 \
		trustedzfs.3 tzfs_rename.3 \
		trustedzfs.3 tzfs_clone.3 \
		trustedzfs.3 tzfs_send.3 \
		trustedzfs.3 tzfs_recv.3 \
		trustedzfs.3 tzfs_blkopen.3

.include <bsd.lib.mk>
