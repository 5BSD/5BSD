/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS dataset handles: capability file descriptors over the ZFS
 * management plane.  See docs/trustedzfs-design.md.
 *
 * A handle pins a dataset by (pool guid, dsobj, dataset guid) and carries a
 * rights mask fixed at creation.  Handles are minted by name via an ioctl on
 * /dev/zfs (the only name-based step) and thereafter addressed only through
 * the descriptor; they may be narrowed (ZFD_DERIVE), extended down the
 * namespace (ZFD_OPENAT, subtree handles only), passed over unix sockets,
 * and further confined with cap_rights_limit()/cap_ioctls_limit().
 */

#ifndef _SYS_ZFSHANDLE_H_
#define	_SYS_ZFSHANDLE_H_

#include <sys/ioccom.h>
#include <sys/types.h>

#define	ZFSHANDLE_NAME_MAX	256	/* == ZFS_MAX_DATASET_NAME_LEN */

/*
 * Rights.  ZH_PROPS_READ and ZH_EVENT are implicit: they are granted to
 * every handle at mint time and cannot be dropped, since a handle that can
 * be neither inspected nor watched is useless.
 */
#define	ZH_PROPS_READ	0x0000000000000001ULL	/* get props/stat/list */
#define	ZH_PROPS_WRITE	0x0000000000000002ULL	/* set properties */
#define	ZH_SNAPSHOT	0x0000000000000004ULL	/* create snapshots */
#define	ZH_SNAP_DESTROY	0x0000000000000008ULL	/* destroy snapshots */
#define	ZH_ROLLBACK	0x0000000000000010ULL	/* rollback to snapshot */
#define	ZH_CLONE_SRC	0x0000000000000020ULL	/* act as clone origin */
#define	ZH_CREATE	0x0000000000000040ULL	/* create children */
#define	ZH_DESTROY	0x0000000000000080ULL	/* destroy datasets */
#define	ZH_SEND		0x0000000000000100ULL	/* serialize as stream */
#define	ZH_RECV		0x0000000000000200ULL	/* receive streams */
#define	ZH_MOUNT	0x0000000000000400ULL	/* anonymous mount / blkopen */
#define	ZH_HOLD		0x0000000000000800ULL	/* snapshot holds */
#define	ZH_EVENT	0x0000000000001000ULL	/* kqueue (implicit) */
#define	ZH_SCRUB	0x0000000000002000ULL	/* pool handles: scrub ctl */

#define	ZH_IMPLICIT_RIGHTS	(ZH_PROPS_READ | ZH_EVENT)
#define	ZH_ALL_RIGHTS		0x0000000000003fffULL

/* Handle flags. */
#define	ZHF_SUBTREE	0x00000001	/* handle covers descendants */

/*
 * Minting (on /dev/zfs).  Command numbers live above the upstream OpenZFS
 * ioctl vector range and are intercepted in zfsdev_ioctl() before the
 * zfs_iocparm_t envelope check.
 */
struct zfs_dataset_open_args {
	char		zdo_name[ZFSHANDLE_NAME_MAX];	/* in: dataset name */
	uint64_t	zdo_rights;			/* in: ZH_* mask */
	uint32_t	zdo_flags;			/* in: ZHF_* */
	int32_t		zdo_fd;				/* out: handle fd */
};

#define	ZFS_IOC_DATASET_OPEN	_IOWR('Z', 0xf0, struct zfs_dataset_open_args)

/*
 * Pool handles (Phase 4): deliberately thin.  Same descriptor type, pool
 * scope: ZPD_STAT/props/scrub plus the one-way ZPD_ROOT_OPEN bridge down
 * to a dataset handle.  Import/export/vdev surgery are NOT delegable.
 */
struct zfs_pool_open_args {
	char		zpo_name[ZFSHANDLE_NAME_MAX];	/* in: pool name */
	uint64_t	zpo_rights;			/* in: ZH_* mask */
	int32_t		zpo_fd;				/* out: handle fd */
	uint32_t	zpo_pad;
};

#define	ZFS_IOC_POOL_OPEN	_IOWR('Z', 0xf1, struct zfs_pool_open_args)

struct zpd_stat_args {
	uint64_t	zp_guid;		/* out */
	uint64_t	zp_size;		/* out: bytes */
	uint64_t	zp_alloc;		/* out: bytes */
	uint64_t	zp_free;		/* out: bytes */
	uint32_t	zp_state;		/* out: pool_state_t */
	uint32_t	zp_scan_func;		/* out: 0 none, 1 scrub, 2 resilver */
	uint32_t	zp_scan_state;		/* out: dsl_scan_state_t */
	uint32_t	zp_pad;
	uint64_t	zp_scan_examined;	/* out: bytes */
	uint64_t	zp_scan_to_examine;	/* out: bytes */
};

#define	ZPD_SCRUB_STOP	0
#define	ZPD_SCRUB_START	1
#define	ZPD_SCRUB_PAUSE	2

struct zpd_scrub_args {
	uint32_t	zs_cmd;			/* in: ZPD_SCRUB_* */
	uint32_t	zs_pad;
};

struct zpd_root_open_args {
	uint64_t	zr_rights;		/* in: dataset rights subset */
	uint32_t	zr_flags;		/* in: ZHF_* */
	int32_t		zr_fd;			/* out: dataset handle fd */
};

#define	ZPD_STAT	_IOR('z', 0x15, struct zpd_stat_args)
#define	ZPD_GET_PROPS	_IOWR('z', 0x16, struct zfd_get_props_args)
#define	ZPD_SET_PROP	_IOW('z', 0x17, struct zfd_set_prop_args)
#define	ZPD_SCRUB	_IOW('z', 0x18, struct zpd_scrub_args)
#define	ZPD_ROOT_OPEN	_IOWR('z', 0x19, struct zpd_root_open_args)

/*
 * Handle operations (fo_ioctl on the handle fd).  Every command is gated on
 * the rights mask; all of them can additionally be allowlisted per-fd with
 * cap_ioctls_limit(2).
 */
struct zfd_info_args {
	uint64_t	zi_ds_guid;		/* out */
	uint64_t	zi_pool_guid;		/* out */
	uint64_t	zi_rights;		/* out */
	uint32_t	zi_flags;		/* out: ZHF_* */
	uint32_t	zi_valid;		/* out: 0 = invalidated */
	char		zi_name[ZFSHANDLE_NAME_MAX]; /* out: current name */
};

struct zfd_derive_args {
	uint64_t	zd_rights;		/* in: subset of parent */
	int32_t		zd_fd;			/* out: new handle fd */
	uint32_t	zd_pad;
};

struct zfd_openat_args {
	char		zo_relname[ZFSHANDLE_NAME_MAX]; /* in: child or @snap */
	uint64_t	zo_rights;		/* in: subset of parent */
	uint32_t	zo_flags;		/* in: ZHF_* for the child */
	int32_t		zo_fd;			/* out: new handle fd */
};

struct zfd_stat_args {
	uint64_t	zs_ds_guid;		/* out */
	uint64_t	zs_referenced;		/* out: bytes */
	uint64_t	zs_available;		/* out: bytes */
	uint64_t	zs_creation_txg;	/* out */
};

struct zfd_snapshot_args {
	char		zsn_snapname[ZFSHANDLE_NAME_MAX]; /* in: component */
};

struct zfd_rollback_args {
	char		zr_snapname[ZFSHANDLE_NAME_MAX]; /* in: component or "" */
};

struct zfd_get_props_args {
	uint64_t	zgp_buf;		/* in: user buffer address */
	uint64_t	zgp_buflen;		/* in: buffer size */
	uint64_t	zgp_size;		/* out: packed nvlist size */
};

/*
 * Enumeration (implicit ZH_PROPS_READ).  LIST_CHILDREN and LIST_SNAPS
 * return a packed nvlist whose keys are the full dataset/snapshot names
 * (values are boolean_t present), via the same buffer protocol as
 * GET_PROPS: the kernel iterates the whole set, cursor-free from the
 * caller's view.  LIST_CHILDREN requires a subtree handle.  HOLDS and
 * LIST_BOOKMARKS reuse the same struct and protocol.
 */

/* Single-property read: the cheap monitor primitive next to STAT. */
struct zfd_get_one_prop_args {
	char		zgo_name[ZFSHANDLE_NAME_MAX];	/* in: property */
	char		zgo_strval[ZFSHANDLE_NAME_MAX];	/* out: string form */
	uint64_t	zgo_intval;			/* out: numeric form */
	uint32_t	zgo_is_string;			/* out: which is live */
	uint32_t	zgo_source;			/* out: zprop_source_t */
};

struct zfd_inherit_args {
	char		zin_name[ZFSHANDLE_NAME_MAX];	/* in: property */
	uint32_t	zin_received;			/* in: revert to recv'd */
	uint32_t	zin_pad;
};

struct zfd_bookmark_args {
	char		zbm_snapname[ZFSHANDLE_NAME_MAX]; /* in: source snap
			    component; "" if handle is a snapshot handle */
	char		zbm_bookname[ZFSHANDLE_NAME_MAX]; /* in: bookmark
			    component (the part after '#') */
};

#define	ZFD_WAIT_DELETEQ	0	/* == ZFS_WAIT_DELETEQ */

struct zfd_wait_args {
	uint32_t	zw_activity;		/* in: ZFD_WAIT_* */
	uint32_t	zw_waited;		/* out: did we block? */
};

struct zfd_set_prop_args {
	char		zsp_name[ZFSHANDLE_NAME_MAX];	/* in: property name */
	char		zsp_strval[ZFSHANDLE_NAME_MAX];	/* in: string value */
	uint64_t	zsp_intval;		/* in: numeric value */
	uint32_t	zsp_is_string;		/* in: which value is live */
	uint32_t	zsp_pad;
};

/* Dataset lifecycle (Phase 2). */
#define	ZFD_TYPE_FILESYSTEM	0
#define	ZFD_TYPE_VOLUME		1

struct zfd_create_args {
	char		zc_relname[ZFSHANDLE_NAME_MAX];	/* in: child name */
	uint32_t	zc_type;		/* in: ZFD_TYPE_* */
	uint32_t	zc_handle_flags;	/* in: ZHF_* for child handle */
	uint64_t	zc_volsize;		/* in: volumes only */
	uint64_t	zc_volblocksize;	/* in: 0 = default */
	int32_t		zc_fd;			/* out: child handle fd */
	uint32_t	zc_pad;
};

struct zfd_destroy_args {
	char		zd_relname[ZFSHANDLE_NAME_MAX]; /* in: "" = self */
	uint32_t	zd_defer;		/* in: defer snapshots */
	uint32_t	zd_pad;
};

struct zfd_rename_args {
	char		zr_from[ZFSHANDLE_NAME_MAX];	/* in: "" = self */
	char		zr_to[ZFSHANDLE_NAME_MAX];	/* in: new relative name */
};

struct zfd_clone_args {
	char		zc_relname[ZFSHANDLE_NAME_MAX];	/* in: clone name here */
	char		zc_origin_snap[ZFSHANDLE_NAME_MAX]; /* in: snap component
			    on the origin handle; "" if origin is a snapshot
			    handle already */
	int32_t		zc_origin_fd;		/* in: handle w/ ZH_CLONE_SRC */
	int32_t		zc_fd;			/* out: clone handle fd */
};

/* Streams (Phase 2). */
#define	ZFD_SEND_EMBED		0x01
#define	ZFD_SEND_LARGEBLOCK	0x02
#define	ZFD_SEND_COMPRESS	0x04
#define	ZFD_SEND_RAW		0x08
/*
 * Send-once semantics (enforced in kernel handle state, so they survive
 * SCM_RIGHTS and cannot be evaded by a non-cooperating holder).  The
 * output fd is never touched by the kernel — closing it is the caller's
 * business; these flags govern the SEND right on the handle itself:
 *   ZFD_SEND_ONCE      after this send, refuse further sends (EALREADY).
 *   ZFD_SEND_CONSUME   with ONCE, fully invalidate the handle afterward
 *                      (ENXIO on everything) rather than leaving it open
 *                      and merely unsendable.
 */
#define	ZFD_SEND_ONCE		0x10
#define	ZFD_SEND_CONSUME	0x20

struct zfd_send_args {
	char		zs_snapname[ZFSHANDLE_NAME_MAX]; /* in: snap component;
			    "" if this handle is a snapshot handle */
	char		zs_fromsnap[ZFSHANDLE_NAME_MAX]; /* in: incremental
			    source component, "" = full stream */
	int32_t		zs_out_fd;		/* in: stream sink (CAP_WRITE) */
	uint32_t	zs_flags;		/* in: ZFD_SEND_* */
};

#define	ZFD_BEGIN_RECORD_SIZE	312	/* sizeof(dmu_replay_record_t) */

struct zfd_recv_args {
	char		zr_reltarget[ZFSHANDLE_NAME_MAX]; /* in: "child@snap"
			    or "@snap" */
	int32_t		zr_input_fd;		/* in: stream source (CAP_READ) */
	uint32_t	zr_force;		/* in: rollback target first */
	uint8_t		zr_begin_record[ZFD_BEGIN_RECORD_SIZE]; /* in: the
			    stream's BEGIN record, read by the caller */
};

#define	ZFD_HOLD_TAG_MAX	256

struct zfd_hold_args {
	char		zh_snapname[ZFSHANDLE_NAME_MAX]; /* in: snap component;
			    "" if this handle is a snapshot handle */
	char		zh_tag[ZFD_HOLD_TAG_MAX];	/* in: hold tag */
};

/* zvol data-plane bridge (Phase 3 slice). */
struct zfd_blkopen_args {
	uint32_t	zb_write;		/* in: 0 = read-only */
	int32_t		zb_fd;			/* out: block device fd */
};

/*
 * Anonymous mount (Phase 3): mount the handle's filesystem WITHOUT
 * attaching it to the global namespace and return a directory fd of its
 * root.  The mount is invisible to path lookup; the dirfd (openat/
 * getdirentries/mmap under it) is the only way in.  The handle anchors
 * the mount: ZFD_UNMOUNT or closing the handle forcibly unmounts, after
 * which operations on the dirfd fail.  One anonymous mount per handle.
 */
struct zfd_mount_args {
	uint32_t	zm_rdonly;		/* in: 0 = read-write */
	int32_t		zm_fd;			/* out: root directory fd */
};

#define	ZFD_INFO	_IOR('z', 0x01, struct zfd_info_args)
#define	ZFD_DERIVE	_IOWR('z', 0x02, struct zfd_derive_args)
#define	ZFD_OPENAT	_IOWR('z', 0x03, struct zfd_openat_args)
#define	ZFD_STAT	_IOR('z', 0x04, struct zfd_stat_args)
#define	ZFD_SNAPSHOT	_IOW('z', 0x05, struct zfd_snapshot_args)
#define	ZFD_SNAP_DESTROY _IOW('z', 0x06, struct zfd_snapshot_args)
#define	ZFD_ROLLBACK	_IOW('z', 0x07, struct zfd_rollback_args)
#define	ZFD_GET_PROPS	_IOWR('z', 0x08, struct zfd_get_props_args)
#define	ZFD_SET_PROP	_IOW('z', 0x09, struct zfd_set_prop_args)
#define	ZFD_CREATE	_IOWR('z', 0x0a, struct zfd_create_args)
#define	ZFD_DESTROY	_IOW('z', 0x0b, struct zfd_destroy_args)
#define	ZFD_RENAME	_IOW('z', 0x0c, struct zfd_rename_args)
#define	ZFD_CLONE	_IOWR('z', 0x0d, struct zfd_clone_args)
#define	ZFD_SEND	_IOW('z', 0x0e, struct zfd_send_args)
#define	ZFD_RECV	_IOW('z', 0x0f, struct zfd_recv_args)
#define	ZFD_HOLD	_IOW('z', 0x10, struct zfd_hold_args)
#define	ZFD_RELEASE	_IOW('z', 0x11, struct zfd_hold_args)
#define	ZFD_BLKOPEN	_IOWR('z', 0x12, struct zfd_blkopen_args)
#define	ZFD_MOUNT	_IOWR('z', 0x13, struct zfd_mount_args)
#define	ZFD_UNMOUNT	_IO('z', 0x14)
/* 0x15-0x19 reserved for the ZPD_* pool verbs above. */
#define	ZFD_LIST_CHILDREN _IOWR('z', 0x1a, struct zfd_get_props_args)
#define	ZFD_LIST_SNAPS	_IOWR('z', 0x1b, struct zfd_get_props_args)
#define	ZFD_GET_ONE_PROP _IOWR('z', 0x1c, struct zfd_get_one_prop_args)
#define	ZFD_HOLDS	_IOWR('z', 0x1d, struct zfd_get_props_args)
#define	ZFD_INHERIT	_IOW('z', 0x1e, struct zfd_inherit_args)
#define	ZFD_PROMOTE	_IO('z', 0x1f)
#define	ZFD_BOOKMARK	_IOW('z', 0x20, struct zfd_bookmark_args)
#define	ZFD_LIST_BOOKMARKS _IOWR('z', 0x21, struct zfd_get_props_args)
#define	ZFD_DESTROY_BOOKMARK _IOW('z', 0x22, struct zfd_bookmark_args)
#define	ZFD_WAIT	_IOWR('z', 0x23, struct zfd_wait_args)
#define	ZPD_WAIT	_IOWR('z', 0x24, struct zfd_wait_args)

#ifdef _KERNEL
struct thread;

/* Hooks called from the FreeBSD zfs module's /dev/zfs ioctl entry. */
int	zfs_handle_is_mint_ioctl(u_long cmd);
int	zfs_handle_mint_ioctl(u_long cmd, void *arg, struct thread *td);
#endif

#endif /* !_SYS_ZFSHANDLE_H_ */
