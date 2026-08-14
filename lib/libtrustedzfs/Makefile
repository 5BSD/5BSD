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
		trustedzfs.3 tzfs_blkopen.3 \
		trustedzfs.3 tzfs_mount.3 \
		trustedzfs.3 tzfs_unmount.3 \
		trustedzfs.3 tzfs_pool_open.3 \
		trustedzfs.3 tzfs_pool_stat.3 \
		trustedzfs.3 tzfs_pool_get_props.3 \
		trustedzfs.3 tzfs_pool_set_prop_string.3 \
		trustedzfs.3 tzfs_pool_scrub.3 \
		trustedzfs.3 tzfs_pool_root_open.3 \
		trustedzfs.3 tzfs_list_children.3 \
		trustedzfs.3 tzfs_list_snapshots.3 \
		trustedzfs.3 tzfs_holds.3 \
		trustedzfs.3 tzfs_list_bookmarks.3 \
		trustedzfs.3 tzfs_get_one_prop.3 \
		trustedzfs.3 tzfs_inherit.3 \
		trustedzfs.3 tzfs_promote.3 \
		trustedzfs.3 tzfs_bookmark.3 \
		trustedzfs.3 tzfs_destroy_bookmark.3 \
		trustedzfs.3 tzfs_wait.3 \
		trustedzfs.3 tzfs_pool_wait.3

.include <bsd.lib.mk>
