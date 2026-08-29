// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 5BSD Project
 *
 * TrustedZFS dataset handles: capability file descriptors over the ZFS
 * management plane.  See docs/trustedzfs-design.md.
 *
 * A handle pins a dataset by (pool guid, dsobj, dataset guid).  Operations
 * hold the dataset by object number and verify the guid, so handles follow
 * renames and observe destroys as ENXIO.  Rights are fixed at mint time and
 * only shrink across ZFD_DERIVE/ZFD_OPENAT.  Minting is the only name-based
 * step and reuses the existing authorization layers (zfs allow delegation,
 * jail dataset visibility); after minting, no ambient checks apply.
 *
 * This file is FreeBSD-only and never merged upstream.  Verbs are
 * implemented as a shim over existing name-based DSL entry points: resolve
 * the pinned object to its current name, then call the same code the
 * name-based ioctls use.  A namespace gate excludes ordinary name-changing
 * ioctls from resolution through the final call, closing replacement races.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/nvpair.h>
#include <sys/poll.h>
#include <sys/policy.h>
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/selinfo.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/user.h>
#include <sys/zfshandle.h>
#include <sys/zone.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_deleg.h>
#include <sys/dsl_destroy.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_scan.h>
#include <sys/dsl_userhold.h>
#include <sys/freebsd_event.h>
#include <sys/metaslab.h>
#include <sys/fs/zfs.h>
#include <sys/spa.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_ioctl_impl.h>
#include <sys/zvol.h>

#include "zfs_namecheck.h"
#include "zfs_prop.h"

SDT_PROVIDER_DEFINE(trustedzfs);
SDT_PROBE_DEFINE3(trustedzfs, , , mint,
    "char *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE3(trustedzfs, , , derive,
    "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE4(trustedzfs, , , handle__openat,
    "uint64_t", "char *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE3(trustedzfs, , , op__entry,
    "uint64_t", "int", "uint64_t");
SDT_PROBE_DEFINE3(trustedzfs, , , op__return,
    "uint64_t", "int", "int");
SDT_PROBE_DEFINE4(trustedzfs, , , denied,
    "uint64_t", "int", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE2(trustedzfs, , , invalidate,
    "uint64_t", "int");

/* invalidate reasons */
#define	ZH_INVAL_GUID_MISS	1
#define	ZH_INVAL_DESTROYED	2
#define	ZH_NVLIST_MAX		(16U * 1024U * 1024U)

/* Internal handle flag: this handle denotes a pool, not a dataset. */
#define	ZHF_POOL		0x40000000

typedef enum zfshandle_send_status {
	ZH_SEND_READY = 0,
	ZH_SEND_RUNNING,
	ZH_SEND_SPENT,
} zfshandle_send_status_t;

struct zfshandle;
TAILQ_HEAD(zfshandle_send_head, zfshandle);

typedef struct zfshandle_send_state {
	volatile u_int	zss_refs;
	kmutex_t	zss_lock;
	zfshandle_send_status_t zss_status;
	boolean_t	zss_consumed;
	struct zfshandle_send_head zss_handles;
} zfshandle_send_state_t;

typedef struct zfshandle {
	uint64_t	zh_pool_guid;
	uint64_t	zh_dsobj;
	uint64_t	zh_ds_guid;
	uint64_t	zh_rights;
	zfd_opset_t	zh_ops;
	uint32_t	zh_flags;
	boolean_t	zh_invalid;
	kmutex_t	zh_lock;		/* struct sx underneath */
	struct selinfo	zh_sel;
	struct mount	*zh_anon_mp;		/* anonymous mount anchor */
	boolean_t	zh_anon_mounting;
	zfshandle_send_state_t *zh_send;
	TAILQ_ENTRY(zfshandle) zh_send_link;
	char		zh_name[ZFSHANDLE_NAME_MAX]; /* last resolved name */
} zfshandle_t;

/*
 * Object-to-name compatibility gate.  Ordinary /dev/zfs operations take the
 * shared side while one handle operation takes the exclusive side from
 * object resolution through the final name-based call.  This makes the shim
 * race-free until the affected OpenZFS entry points grow object-based forms.
 */
static struct sx zfshandle_namespace_sx;
static volatile u_int zfshandle_live;
static int zfshandle_enum_max_entries = ZFSHANDLE_ENUM_MAX_ENTRIES;

SYSCTL_DECL(_vfs_zfs);
SYSCTL_NODE(_vfs_zfs, OID_AUTO, trustedzfs, CTLFLAG_RD, 0,
    "TrustedZFS capability handles");
SYSCTL_INT(_vfs_zfs_trustedzfs, OID_AUTO, enum_max_entries, CTLFLAG_RDTUN,
    &zfshandle_enum_max_entries, 0,
    "Maximum entries returned by one cursor-free enumeration");

void
zfs_handle_init(void)
{
	/* The boot tunable may make tests/policies stricter, never looser. */
	if (zfshandle_enum_max_entries <= 0 ||
	    zfshandle_enum_max_entries > ZFSHANDLE_ENUM_MAX_ENTRIES)
		zfshandle_enum_max_entries = ZFSHANDLE_ENUM_MAX_ENTRIES;
	sx_init(&zfshandle_namespace_sx, "TrustedZFS namespace");
}

void
zfs_handle_fini(void)
{
	sx_destroy(&zfshandle_namespace_sx);
}

int
zfs_handle_busy(void)
{
	return (atomic_load_int(&zfshandle_live) != 0);
}

void
zfs_handle_upstream_enter(void)
{
	sx_slock(&zfshandle_namespace_sx);
}

void
zfs_handle_upstream_exit(void)
{
	sx_sunlock(&zfshandle_namespace_sx);
}

void
zfs_handle_mint_enter(void)
{
	sx_xlock(&zfshandle_namespace_sx);
}

void
zfs_handle_mint_exit(void)
{
	sx_xunlock(&zfshandle_namespace_sx);
}

static fo_ioctl_t	zfshandle_ioctl;

static int	zfshandle_ioc_flags(uint64_t, const char *, const char *,
		    uint64_t, uint64_t, nvlist_t *, nvlist_t **);
static int	zfshandle_ioc(uint64_t, const char *, const char *,
		    uint64_t, nvlist_t *, nvlist_t **);
static int	zfshandle_mint_child(struct thread *, struct zfshandle *,
		    const char *, uint64_t, uint32_t, int32_t *);
static fo_poll_t	zfshandle_poll;
static fo_kqfilter_t	zfshandle_kqfilter;
static fo_stat_t	zfshandle_stat;
static fo_close_t	zfshandle_close;
static fo_fill_kinfo_t	zfshandle_fill_kinfo;

static const struct fileops zfshandle_ops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = zfshandle_ioctl,
	.fo_poll = zfshandle_poll,
	.fo_kqfilter = zfshandle_kqfilter,
	.fo_stat = zfshandle_stat,
	.fo_close = zfshandle_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = zfshandle_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE
};

static zfshandle_send_state_t *
zfshandle_send_alloc(void)
{
	zfshandle_send_state_t *zss;

	zss = kmem_zalloc(sizeof (*zss), KM_SLEEP);
	zss->zss_refs = 1;
	mutex_init(&zss->zss_lock, "zfshandle send", MUTEX_DEFAULT, NULL);
	TAILQ_INIT(&zss->zss_handles);
	return (zss);
}

static void
zfshandle_send_hold(zfshandle_send_state_t *zss)
{
	atomic_add_int(&zss->zss_refs, 1);
}

static void
zfshandle_send_rele(zfshandle_send_state_t *zss)
{

	if (atomic_fetchadd_int(&zss->zss_refs, -1) != 1)
		return;
	mutex_destroy(&zss->zss_lock);
	kmem_free(zss, sizeof (*zss));
}

static void
zfshandle_send_share(zfshandle_t *child, zfshandle_t *parent)
{
	zfshandle_send_state_t *old, *shared;

	old = child->zh_send;
	mutex_enter(&old->zss_lock);
	TAILQ_REMOVE(&old->zss_handles, child, zh_send_link);
	mutex_exit(&old->zss_lock);
	zfshandle_send_rele(old);

	shared = parent->zh_send;
	zfshandle_send_hold(shared);
	child->zh_send = shared;
	mutex_enter(&shared->zss_lock);
	TAILQ_INSERT_TAIL(&shared->zss_handles, child, zh_send_link);
	mutex_exit(&shared->zss_lock);
}

static boolean_t
zfshandle_is_invalid(zfshandle_t *zh)
{
	boolean_t invalid;

	mutex_enter(&zh->zh_lock);
	invalid = zh->zh_invalid;
	mutex_exit(&zh->zh_lock);
	if (invalid)
		return (B_TRUE);
	mutex_enter(&zh->zh_send->zss_lock);
	invalid = zh->zh_send->zss_consumed;
	mutex_exit(&zh->zh_send->zss_lock);
	return (invalid);
}

static zfd_opset_t
zfshandle_dataset_profile(uint64_t rights, uint32_t flags)
{
	zfd_opset_t ops;

	ops = ZFD_OP_INFO | ZFD_OP_DERIVE | ZFD_OP_OPENAT | ZFD_OP_STAT |
	    ZFD_OP_GET_PROPS |
	    ZFD_OP_GET_ONE_PROP | ZFD_OP_LIST_SNAPSHOTS | ZFD_OP_HOLDS |
	    ZFD_OP_LIST_BOOKMARKS;
	if ((flags & ZHF_SUBTREE) != 0)
		ops |= ZFD_OP_LIST_CHILDREN;
	if ((rights & ZH_PROPS_WRITE) != 0)
		ops |= ZFD_OP_SET_PROP | ZFD_OP_INHERIT;
	if ((rights & ZH_SNAPSHOT) != 0)
		ops |= ZFD_OP_SNAPSHOT;
	if ((rights & ZH_BOOKMARK) != 0)
		ops |= ZFD_OP_BOOKMARK;
	if ((rights & ZH_SNAP_DESTROY) != 0)
		ops |= ZFD_OP_SNAP_DESTROY | ZFD_OP_DESTROY_BOOKMARK;
	if ((rights & ZH_ROLLBACK) != 0)
		ops |= ZFD_OP_ROLLBACK;
	if ((rights & ZH_CREATE) != 0)
		ops |= ZFD_OP_CREATE | ZFD_OP_CLONE;
	if ((rights & ZH_DESTROY) != 0)
		ops |= ZFD_OP_DESTROY;
	if ((rights & ZH_RENAME) != 0)
		ops |= ZFD_OP_RENAME;
	if ((rights & ZH_PROMOTE) != 0)
		ops |= ZFD_OP_PROMOTE;
	if ((rights & ZH_SEND) != 0)
		ops |= ZFD_OP_SEND;
	if ((rights & ZH_RECV) != 0)
		ops |= ZFD_OP_RECV;
	if ((rights & ZH_MOUNT) != 0)
		ops |= ZFD_OP_BLKOPEN | ZFD_OP_MOUNT | ZFD_OP_UNMOUNT;
	if ((rights & ZH_HOLD) != 0)
		ops |= ZFD_OP_HOLD;
	if ((rights & ZH_RELEASE) != 0)
		ops |= ZFD_OP_RELEASE;
	if ((rights & ZH_CLONE_SRC) != 0)
		ops |= ZFD_OP_CLONE_SOURCE;
	return (ops);
}

static zfd_opset_t
zfshandle_pool_profile(uint64_t rights)
{
	zfd_opset_t ops;

	ops = ZFD_OP_INFO | ZFD_OP_DERIVE | ZFD_OP_POOL_STAT |
	    ZFD_OP_POOL_GET_PROPS | ZFD_OP_POOL_ROOT_OPEN;
	if ((rights & ZH_PROPS_WRITE) != 0)
		ops |= ZFD_OP_POOL_SET_PROP;
	if ((rights & ZH_SCRUB) != 0)
		ops |= ZFD_OP_POOL_SCRUB;
	return (ops);
}

static int
zfshandle_flags_validate(uint32_t flags)
{

	if ((flags & ~ZHF_ALL) != 0 ||
	    ((flags & ZHF_SEND_CONSUME) != 0 &&
	    (flags & ZHF_SEND_ONCE) == 0))
		return (SET_ERROR(EINVAL));
	return (0);
}

static int
zfshandle_child_flags(zfshandle_t *parent, uint32_t requested,
    uint32_t *result)
{
	int error;

	error = zfshandle_flags_validate(requested);
	if (error != 0)
		return (error);
	requested |= parent->zh_flags & (ZHF_SEND_ONCE | ZHF_SEND_CONSUME);
	*result = requested;
	return (0);
}

static void
zfshandle_free(zfshandle_t *zh)
{
	seldrain(&zh->zh_sel);
	knlist_clear(&zh->zh_sel.si_note, 0);
	knlist_destroy(&zh->zh_sel.si_note);
	mutex_enter(&zh->zh_send->zss_lock);
	TAILQ_REMOVE(&zh->zh_send->zss_handles, zh, zh_send_link);
	mutex_exit(&zh->zh_send->zss_lock);
	zfshandle_send_rele(zh->zh_send);
	mutex_destroy(&zh->zh_lock);
	atomic_add_int(&zfshandle_live, -1);
	kmem_free(zh, sizeof (*zh));
}

static zfshandle_t *
zfshandle_alloc(uint64_t pool_guid, uint64_t dsobj, uint64_t ds_guid,
    uint64_t rights, uint32_t flags, const char *name)
{
	zfshandle_t *zh;

	zh = kmem_zalloc(sizeof (*zh), KM_SLEEP);
	zh->zh_pool_guid = pool_guid;
	zh->zh_dsobj = dsobj;
	zh->zh_ds_guid = ds_guid;
	zh->zh_rights = rights | ZH_IMPLICIT_RIGHTS;
	zh->zh_flags = flags;
	zh->zh_ops = (flags & ZHF_POOL) != 0 ?
	    zfshandle_pool_profile(zh->zh_rights) :
	    zfshandle_dataset_profile(zh->zh_rights, flags);
	zh->zh_send = zfshandle_send_alloc();
	mutex_init(&zh->zh_lock, "zfshandle", MUTEX_DEFAULT, NULL);
	knlist_init_sx(&zh->zh_sel.si_note, &zh->zh_lock);
	(void) strlcpy(zh->zh_name, name, sizeof (zh->zh_name));
	mutex_enter(&zh->zh_send->zss_lock);
	TAILQ_INSERT_TAIL(&zh->zh_send->zss_handles, zh, zh_send_link);
	mutex_exit(&zh->zh_send->zss_lock);
	atomic_add_int(&zfshandle_live, 1);
	return (zh);
}

static void
zfshandle_invalidate(zfshandle_t *zh, int reason)
{
	mutex_enter(&zh->zh_lock);
	if (!zh->zh_invalid) {
		zh->zh_invalid = B_TRUE;
		SDT_PROBE2(trustedzfs, , , invalidate, zh->zh_ds_guid, reason);
		selwakeup(&zh->zh_sel);
	}
	mutex_exit(&zh->zh_lock);
	KNOTE_UNLOCKED(&zh->zh_sel.si_note, 0);
}

/*
 * Resolve the pinned dataset: hold the pool by guid, hold the dataset by
 * object number, verify the guid witness.  On success the caller owns a
 * dataset hold and a pool hold (release with zfshandle_rele()) and
 * zh_name has been refreshed.  Guid mismatch and dead-object are sticky
 * invalidation; a missing pool (exported) is transient ENXIO so that a
 * re-imported pool revives the handle.
 */
static int
zfshandle_hold(zfshandle_t *zh, const void *tag, dsl_pool_t **dpp,
    dsl_dataset_t **dsp)
{
	char pname[ZFS_MAX_DATASET_NAME_LEN];
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	spa_t *spa;
	int error;

	if (zfshandle_is_invalid(zh))
		return (SET_ERROR(ENXIO));

	spa_namespace_enter(FTAG);
	spa = spa_by_guid(zh->zh_pool_guid, 0);
	if (spa == NULL) {
		spa_namespace_exit(FTAG);
		return (SET_ERROR(ENXIO));
	}
	(void) strlcpy(pname, spa_name(spa), sizeof (pname));
	spa_namespace_exit(FTAG);

	error = dsl_pool_hold(pname, tag, &dp);
	if (error != 0)
		return (SET_ERROR(ENXIO));
	if (spa_guid(dp->dp_spa) != zh->zh_pool_guid) {
		dsl_pool_rele(dp, tag);
		return (SET_ERROR(ENXIO));
	}

	error = dsl_dataset_hold_obj(dp, zh->zh_dsobj, tag, &ds);
	if (error != 0) {
		dsl_pool_rele(dp, tag);
		zfshandle_invalidate(zh, ZH_INVAL_DESTROYED);
		return (SET_ERROR(ENXIO));
	}
	if (dsl_dataset_phys(ds)->ds_guid != zh->zh_ds_guid) {
		dsl_dataset_rele(ds, tag);
		dsl_pool_rele(dp, tag);
		zfshandle_invalidate(zh, ZH_INVAL_GUID_MISS);
		return (SET_ERROR(ENXIO));
	}

	mutex_enter(&zh->zh_lock);
	dsl_dataset_name(ds, zh->zh_name);
	mutex_exit(&zh->zh_lock);

	*dpp = dp;
	*dsp = ds;
	return (0);
}

static void
zfshandle_rele(dsl_pool_t *dp, dsl_dataset_t *ds, const void *tag)
{
	dsl_dataset_rele(ds, tag);
	dsl_pool_rele(dp, tag);
}

/*
 * Resolve to a name and drop the holds, for verbs that call name-based DSL
 * entry points (which take their own pool holds and would deadlock against
 * ours).
 */
static int
zfshandle_resolve_name(zfshandle_t *zh, char *name, size_t namelen)
{
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	int error;

	error = zfshandle_hold(zh, FTAG, &dp, &ds);
	if (error != 0)
		return (error);
	dsl_dataset_name(ds, name);
	zfshandle_rele(dp, ds, FTAG);
	return (0);
}

static int
zfshandle_require(zfshandle_t *zh, u_long cmd, uint64_t rights)
{
	if ((zh->zh_rights & rights) != rights) {
		SDT_PROBE4(trustedzfs, , , denied, zh->zh_ds_guid, (int)cmd,
		    rights, zh->zh_rights);
		return (SET_ERROR(EPERM));
	}
	return (0);
}

static int
zfshandle_str_validate(const char *str, size_t len, boolean_t required)
{

	if (memchr(str, '\0', len) == NULL)
		return (SET_ERROR(EINVAL));
	if (required && str[0] == '\0')
		return (SET_ERROR(EINVAL));
	return (0);
}

/* Reject traversal components without rejecting ordinary names containing .. */
static int
zfshandle_relpath_validate(const char *path)
{
	const char *component, *slash;
	size_t len;

	if (path[0] == '/')
		return (SET_ERROR(EINVAL));
	component = path;
	for (;;) {
		slash = strchr(component, '/');
		len = slash == NULL ? strlen(component) :
		    (size_t)(slash - component);
		if ((len == 1 && component[0] == '.') ||
		    (len == 2 && component[0] == '.' && component[1] == '.'))
			return (SET_ERROR(EINVAL));
		if (slash == NULL)
			break;
		component = slash + 1;
	}
	return (0);
}

/*
 * Install a new handle as a file descriptor in td's fd table.  Consumes zh
 * (frees it on error via fo_close semantics).
 */
static int
zfshandle_install(struct thread *td, zfshandle_t *zh, int *fdp)
{
	struct file *fp;
	int error, fd;

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		zfshandle_free(zh);
		return (error);
	}
	finit(fp, FREAD | FWRITE, DTYPE_ZFSHANDLE, zh, &zfshandle_ops);
	error = finstall(td, fp, &fd, O_CLOEXEC, NULL);
	fdrop(fp, td);
	if (error == 0)
		*fdp = fd;
	return (error);
}

/*
 * Mint-time authorization.  Mirrors the ambient model: root (secpolicy_zfs)
 * mints anything visible from its jail; otherwise each requested right must
 * be covered by zfs allow delegation on the dataset.  ZH_PROPS_WRITE has no
 * single delegation equivalent (property permissions are per-property), so
 * non-root minting of it is refused until per-prop allowlists (Phase 2).
 */
static const struct {
	uint64_t	right;
	const char	*perm;
} zfshandle_perm_map[] = {
	{ ZH_SNAPSHOT,		ZFS_DELEG_PERM_SNAPSHOT },
	{ ZH_SNAP_DESTROY,	ZFS_DELEG_PERM_DESTROY },
	{ ZH_SNAP_DESTROY,	ZFS_DELEG_PERM_MOUNT },
	{ ZH_ROLLBACK,		ZFS_DELEG_PERM_ROLLBACK },
	{ ZH_CLONE_SRC,		ZFS_DELEG_PERM_CLONE },
	{ ZH_CREATE,		ZFS_DELEG_PERM_CREATE },
	{ ZH_CREATE,		ZFS_DELEG_PERM_MOUNT },
	{ ZH_DESTROY,		ZFS_DELEG_PERM_DESTROY },
	{ ZH_DESTROY,		ZFS_DELEG_PERM_MOUNT },
	{ ZH_RENAME,		ZFS_DELEG_PERM_RENAME },
	{ ZH_RENAME,		ZFS_DELEG_PERM_MOUNT },
	{ ZH_RENAME,		ZFS_DELEG_PERM_CREATE },
	{ ZH_BOOKMARK,		ZFS_DELEG_PERM_BOOKMARK },
	{ ZH_SEND,		ZFS_DELEG_PERM_SEND },
	{ ZH_RECV,		ZFS_DELEG_PERM_RECEIVE },
	{ ZH_RECV,		ZFS_DELEG_PERM_MOUNT },
	{ ZH_RECV,		ZFS_DELEG_PERM_CREATE },
	{ ZH_MOUNT,		ZFS_DELEG_PERM_MOUNT },
	{ ZH_HOLD,		ZFS_DELEG_PERM_HOLD },
	{ ZH_RELEASE,		ZFS_DELEG_PERM_RELEASE },
};

static int
zfshandle_mint_authorize(const char *name, uint64_t rights, cred_t *cr)
{
	int error, writable;
	size_t i;

	if (!INGLOBALZONE(curproc)) {
		if (!zone_dataset_visible(name, &writable))
			return (SET_ERROR(ENOENT));
		if ((rights & ~ZH_IMPLICIT_RIGHTS) != 0 && writable == 0)
			return (SET_ERROR(EPERM));
	}

	if (secpolicy_zfs(cr) == 0)
		return (0);

	if ((rights & ZH_PROPS_WRITE) != 0)
		return (SET_ERROR(EPERM));
	/* Promote also needs authority over the clone's origin; root only. */
	if ((rights & ZH_PROMOTE) != 0)
		return (SET_ERROR(EPERM));

	for (i = 0; i < nitems(zfshandle_perm_map); i++) {
		if ((rights & zfshandle_perm_map[i].right) == 0)
			continue;
		error = dsl_deleg_access(name, zfshandle_perm_map[i].perm, cr);
		if (error != 0)
			return (error);
	}
	return (0);
}

/* Resolve a pool handle's current pool name; ENXIO when absent. */
static int
zfshandle_pool_name(zfshandle_t *zh, char *name, size_t namelen)
{
	spa_t *spa;

	spa_namespace_enter(FTAG);
	spa = spa_by_guid(zh->zh_pool_guid, 0);
	if (spa == NULL) {
		spa_namespace_exit(FTAG);
		return (SET_ERROR(ENXIO));
	}
	(void) strlcpy(name, spa_name(spa), namelen);
	spa_namespace_exit(FTAG);
	mutex_enter(&zh->zh_lock);
	(void) strlcpy(zh->zh_name, name, sizeof (zh->zh_name));
	mutex_exit(&zh->zh_lock);
	return (0);
}

static int
zfshandle_op_pool_stat(zfshandle_t *zh, struct zpd_stat_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	spa_t *spa;
	dsl_pool_t *dp;
	metaslab_class_t *mc;
	int error;

	error = zfshandle_pool_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	error = spa_open(name, &spa, FTAG);
	if (error != 0)
		return (error);
	if (spa_guid(spa) != zh->zh_pool_guid) {
		spa_close(spa, FTAG);
		return (SET_ERROR(ENXIO));
	}

	bzero(args, sizeof (*args));
	args->zp_guid = zh->zh_pool_guid;
	args->zp_state = spa_state(spa);
	mc = spa_normal_class(spa);
	args->zp_size = metaslab_class_get_space(mc);
	args->zp_alloc = metaslab_class_get_alloc(mc);
	args->zp_free = args->zp_size - args->zp_alloc;
	dp = spa_get_dsl(spa);
	if (dp != NULL && dp->dp_scan != NULL) {
		args->zp_scan_func = dp->dp_scan->scn_phys.scn_func;
		args->zp_scan_state = dp->dp_scan->scn_phys.scn_state;
		args->zp_scan_examined = dp->dp_scan->scn_phys.scn_examined;
		args->zp_scan_to_examine =
		    dp->dp_scan->scn_phys.scn_to_examine;
	}
	spa_close(spa, FTAG);
	return (0);
}

static int
zfshandle_op_pool_get_props(zfshandle_t *zh, struct zfd_get_props_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *nv = NULL;
	char *packed;
	size_t size;
	int error;

	error = zfshandle_pool_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	error = zfshandle_ioc(ZFS_IOC_POOL_GET_PROPS, name, NULL, 0, NULL,
	    &nv);
	if (error != 0)
		return (error);
	if (nv == NULL)
		return (SET_ERROR(EIO));

	packed = fnvlist_pack(nv, &size);
	nvlist_free(nv);
	args->zgp_size = size;
	if (size > ZH_NVLIST_MAX)
		error = SET_ERROR(E2BIG);
	else if (args->zgp_buflen < size)
		error = SET_ERROR(ENOMEM);
	else
		error = copyout(packed, (void *)(uintptr_t)args->zgp_buf,
		    size);
	fnvlist_pack_free(packed, size);
	return (error);
}

static int
zfshandle_op_pool_set_prop(zfshandle_t *zh, struct zfd_set_prop_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *nvl;
	int error;

	if (zfshandle_str_validate(args->zsp_name,
	    sizeof (args->zsp_name), B_TRUE) != 0 ||
	    zfshandle_str_validate(args->zsp_strval,
	    sizeof (args->zsp_strval), B_FALSE) != 0 ||
	    args->zsp_is_string > 1 || args->zsp_pad != 0)
		return (SET_ERROR(EINVAL));
	/* Pool mutation is intentionally only the boot-environment sliver. */
	if (strcmp(args->zsp_name, "bootfs") != 0 || !args->zsp_is_string)
		return (SET_ERROR(EPERM));
	error = zfshandle_pool_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);

	nvl = fnvlist_alloc();
	if (args->zsp_is_string)
		fnvlist_add_string(nvl, args->zsp_name, args->zsp_strval);
	else
		fnvlist_add_uint64(nvl, args->zsp_name, args->zsp_intval);
	error = zfshandle_ioc(ZFS_IOC_POOL_SET_PROPS, name, NULL, 0, nvl,
	    NULL);
	nvlist_free(nvl);
	return (error);
}

static int
zfshandle_op_pool_scrub(zfshandle_t *zh, struct zpd_scrub_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	uint64_t func, flags;
	int error;

	if (args->zs_pad != 0)
		return (SET_ERROR(EINVAL));

	switch (args->zs_cmd) {
	case ZPD_SCRUB_START:
		func = POOL_SCAN_SCRUB;
		flags = POOL_SCRUB_NORMAL;
		break;
	case ZPD_SCRUB_PAUSE:
		func = POOL_SCAN_SCRUB;
		flags = POOL_SCRUB_PAUSE;
		break;
	case ZPD_SCRUB_STOP:
		func = POOL_SCAN_NONE;
		flags = POOL_SCRUB_NORMAL;
		break;
	default:
		return (SET_ERROR(EINVAL));
	}
	error = zfshandle_pool_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	return (zfshandle_ioc_flags(ZFS_IOC_POOL_SCAN, name, NULL, func,
	    flags, NULL, NULL));
}

static int
zfshandle_op_pool_root_open(zfshandle_t *zh, struct zpd_root_open_args *args,
    struct thread *td)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	if ((args->zr_rights & ~ZH_ALL_RIGHTS) != 0 ||
	    zfshandle_flags_validate(args->zr_flags) != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zr_rights & ~zh->zh_rights) != 0)
		return (SET_ERROR(ENOTCAPABLE));
	error = zfshandle_pool_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	return (zfshandle_mint_child(td, zh, name, args->zr_rights,
	    args->zr_flags, &args->zr_fd));
}

int
zfs_handle_is_mint_ioctl(u_long cmd)
{
	return (cmd == ZFS_IOC_DATASET_OPEN || cmd == ZFS_IOC_POOL_OPEN);
}

static int
zfs_handle_mint_pool(struct zfs_pool_open_args *args, struct thread *td)
{
	char name[ZFSHANDLE_NAME_MAX];
	zfshandle_t *zh;
	spa_t *spa;
	uint64_t pool_guid;
	int error, fd, writable;

	if (zfshandle_str_validate(args->zpo_name,
	    sizeof (args->zpo_name), B_TRUE) != 0 || args->zpo_pad != 0)
		return (SET_ERROR(EINVAL));
	(void) strlcpy(name, args->zpo_name, sizeof (name));
	if (strchr(name, '/') != NULL ||
	    strchr(name, '@') != NULL ||
	    pool_namecheck(name, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zpo_rights & ~ZH_ALL_RIGHTS) != 0)
		return (SET_ERROR(EINVAL));

	/*
	 * Pool-level authority has no zfs-allow analogue: anything beyond
	 * the implicit read/watch rights requires root.  Jailed callers
	 * additionally need the pool's root dataset to be visible.
	 */
	if (!INGLOBALZONE(curproc) &&
	    !zone_dataset_visible(name, &writable))
		return (SET_ERROR(ENOENT));
	if ((args->zpo_rights & ~ZH_IMPLICIT_RIGHTS) != 0 &&
	    secpolicy_zfs(td->td_ucred) != 0)
		return (SET_ERROR(EPERM));

	error = spa_open(name, &spa, FTAG);
	if (error != 0)
		return (error);
	pool_guid = spa_guid(spa);
	spa_close(spa, FTAG);

	zh = zfshandle_alloc(pool_guid, 0, pool_guid, args->zpo_rights,
	    ZHF_POOL, name);
	error = zfshandle_install(td, zh, &fd);
	if (error != 0)
		return (error);
	SDT_PROBE3(trustedzfs, , , mint, zh->zh_name, pool_guid,
	    zh->zh_rights);
	args->zpo_fd = fd;
	return (0);
}

int
zfs_handle_mint_ioctl(u_long cmd, void *arg, struct thread *td)
{
	struct zfs_dataset_open_args *args = arg;
	char name[ZFSHANDLE_NAME_MAX];
	zfshandle_t *zh;
	objset_t *os;
	dsl_dataset_t *ds;
	uint64_t pool_guid, dsobj, ds_guid;
	int error, fd;

	if (cmd == ZFS_IOC_POOL_OPEN)
		return (zfs_handle_mint_pool(arg, td));
	if (cmd != ZFS_IOC_DATASET_OPEN)
		return (SET_ERROR(ENOTTY));

	if (zfshandle_str_validate(args->zdo_name,
	    sizeof (args->zdo_name), B_TRUE) != 0)
		return (SET_ERROR(EINVAL));
	(void) strlcpy(name, args->zdo_name, sizeof (name));
	if (
	    entity_namecheck(name, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zdo_rights & ~ZH_ALL_RIGHTS) != 0 ||
	    zfshandle_flags_validate(args->zdo_flags) != 0)
		return (SET_ERROR(EINVAL));

	error = zfshandle_mint_authorize(name, args->zdo_rights,
	    td->td_ucred);
	if (error != 0)
		return (error);

	error = dmu_objset_hold(name, FTAG, &os);
	if (error != 0)
		return (error);
	ds = dmu_objset_ds(os);
	pool_guid = spa_guid(dmu_objset_spa(os));
	dsobj = ds->ds_object;
	ds_guid = dsl_dataset_phys(ds)->ds_guid;
	dmu_objset_rele(os, FTAG);

	zh = zfshandle_alloc(pool_guid, dsobj, ds_guid, args->zdo_rights,
	    args->zdo_flags, name);
	error = zfshandle_install(td, zh, &fd);
	if (error != 0)
		return (error);

	SDT_PROBE3(trustedzfs, , , mint, zh->zh_name, ds_guid,
	    zh->zh_rights);
	args->zdo_fd = fd;
	return (0);
}

/*
 * Verbs.
 */

static int
zfshandle_op_info(zfshandle_t *zh, struct zfd_info_args *args)
{
	char pname[ZFS_MAX_DATASET_NAME_LEN];
	dsl_pool_t *dp;
	dsl_dataset_t *ds;

	bzero(args, sizeof (*args));
	args->zi_ds_guid = zh->zh_ds_guid;
	args->zi_pool_guid = zh->zh_pool_guid;
	args->zi_rights = zh->zh_rights;
	args->zi_flags = zh->zh_flags & ZHF_ALL;
	if (zfshandle_is_invalid(zh)) {
		args->zi_valid = 0;
	} else if (zh->zh_flags & ZHF_POOL) {
		if (zfshandle_pool_name(zh, pname, sizeof (pname)) == 0)
			args->zi_valid = 1;
	} else if (zfshandle_hold(zh, FTAG, &dp, &ds) == 0) {
		args->zi_valid = 1;
		zfshandle_rele(dp, ds, FTAG);
	}
	mutex_enter(&zh->zh_lock);
	(void) strlcpy(args->zi_name, zh->zh_name, sizeof (args->zi_name));
	mutex_exit(&zh->zh_lock);
	return (0);
}

static int
zfshandle_op_stat(zfshandle_t *zh, struct zfd_stat_args *args)
{
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	objset_t *os;
	uint64_t usedobjs, availobjs;
	int error;

	error = zfshandle_hold(zh, FTAG, &dp, &ds);
	if (error != 0)
		return (error);
	error = dmu_objset_from_ds(ds, &os);
	if (error == 0) {
		bzero(args, sizeof (*args));
		args->zs_ds_guid = zh->zh_ds_guid;
		args->zs_creation_txg = dsl_dataset_phys(ds)->ds_creation_txg;
		dmu_objset_space(os, &args->zs_referenced,
		    &args->zs_available, &usedobjs, &availobjs);
	}
	zfshandle_rele(dp, ds, FTAG);
	return (error);
}

static int
zfshandle_op_get_props(zfshandle_t *zh, struct zfd_get_props_args *args)
{
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	objset_t *os;
	nvlist_t *nv;
	char *packed;
	size_t size;
	int error;

	error = zfshandle_hold(zh, FTAG, &dp, &ds);
	if (error != 0)
		return (error);
	error = dmu_objset_from_ds(ds, &os);
	if (error == 0)
		error = dsl_prop_get_all(os, &nv);
	zfshandle_rele(dp, ds, FTAG);
	if (error != 0)
		return (error);

	packed = fnvlist_pack(nv, &size);
	nvlist_free(nv);
	args->zgp_size = size;
	if (size > ZH_NVLIST_MAX)
		error = SET_ERROR(E2BIG);
	else if (args->zgp_buflen < size)
		error = SET_ERROR(ENOMEM);
	else
		error = copyout(packed, (void *)(uintptr_t)args->zgp_buf,
		    size);
	fnvlist_pack_free(packed, size);
	return (error);
}

static int
zfshandle_op_set_prop(zfshandle_t *zh, struct zfd_set_prop_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *nvl;
	int error;

	if (zfshandle_str_validate(args->zsp_name,
	    sizeof (args->zsp_name), B_TRUE) != 0 ||
	    zfshandle_str_validate(args->zsp_strval,
	    sizeof (args->zsp_strval), B_FALSE) != 0 ||
	    args->zsp_is_string > 1 || args->zsp_pad != 0)
		return (SET_ERROR(EINVAL));

	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);

	nvl = fnvlist_alloc();
	if (args->zsp_is_string)
		fnvlist_add_string(nvl, args->zsp_name, args->zsp_strval);
	else
		fnvlist_add_uint64(nvl, args->zsp_name, args->zsp_intval);
	error = dsl_props_set(name, ZPROP_SRC_LOCAL, nvl);
	nvlist_free(nvl);
	return (error);
}

static int
zfshandle_snapname(zfshandle_t *zh, const char *component, char *buf,
    size_t buflen)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	if (component[0] == '\0' ||
	    zfs_component_namecheck(component, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	if (snprintf(buf, buflen, "%s@%s", name, component) >= (int)buflen)
		return (SET_ERROR(ENAMETOOLONG));
	return (0);
}

static int
zfshandle_op_snapshot(zfshandle_t *zh, struct zfd_snapshot_args *args,
    struct ucred *cred)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *snaps;
	int error;

	if (zfshandle_str_validate(args->zsn_snapname,
	    sizeof (args->zsn_snapname), B_TRUE) != 0)
		return (SET_ERROR(EINVAL));
	error = zfshandle_snapname(zh, args->zsn_snapname, full,
	    sizeof (full));
	if (error != 0)
		return (error);
#ifdef MAC
	error = mac_mount_check_snapshot_create(cred, full);
	if (error != 0)
		return (error);
#endif

	snaps = fnvlist_alloc();
	fnvlist_add_boolean(snaps, full);
	error = dsl_dataset_snapshot(snaps, NULL, NULL);
	nvlist_free(snaps);
	return (error);
}

static int
zfshandle_op_snap_destroy(zfshandle_t *zh, struct zfd_snapshot_args *args,
    struct ucred *cred)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	if (zfshandle_str_validate(args->zsn_snapname,
	    sizeof (args->zsn_snapname), B_TRUE) != 0)
		return (SET_ERROR(EINVAL));
	error = zfshandle_snapname(zh, args->zsn_snapname, full,
	    sizeof (full));
	if (error != 0)
		return (error);
#ifdef MAC
	error = mac_zfs_check_dataset_destroy(cred, full);
	if (error == 0)
		error = mac_mount_check_snapshot_delete(cred, full);
	if (error != 0)
		return (error);
#endif
	return (dsl_destroy_snapshot(full, B_FALSE));
}

static int
zfshandle_op_rollback(zfshandle_t *zh, struct zfd_rollback_args *args,
    struct ucred *cred)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char target[ZFS_MAX_DATASET_NAME_LEN];
	const char *tgt = NULL;
	zfsvfs_t *zfsvfs;
	zvol_state_handle_t *zv;
	nvlist_t *outnvl;
	int error;

	if (zfshandle_str_validate(args->zr_snapname,
	    sizeof (args->zr_snapname), B_FALSE) != 0)
		return (SET_ERROR(EINVAL));
	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	if (args->zr_snapname[0] != '\0') {
		if (zfs_component_namecheck(args->zr_snapname, NULL,
		    NULL) != 0)
			return (SET_ERROR(EINVAL));
		if (snprintf(target, sizeof (target), "%s@%s", name,
		    args->zr_snapname) >= (int)sizeof (target))
			return (SET_ERROR(ENAMETOOLONG));
		tgt = target;
	}
#ifdef MAC
	error = mac_mount_check_snapshot_revert(cred,
	    tgt != NULL ? tgt : name);
	if (error != 0)
		return (error);
#endif

	/* Same suspend/resume triad as zfs_ioc_rollback(). */
	outnvl = fnvlist_alloc();
	if (getzfsvfs(name, &zfsvfs) == 0) {
		dsl_dataset_t *ds;

		ds = dmu_objset_ds(zfsvfs->z_os);
		error = zfs_suspend_fs(zfsvfs);
		if (error == 0) {
			int resume_err;

			error = dsl_dataset_rollback(name, tgt, zfsvfs,
			    outnvl);
			resume_err = zfs_resume_fs(zfsvfs, ds);
			error = error ? error : resume_err;
		}
		zfs_vfs_rele(zfsvfs);
	} else if (zvol_suspend(name, &zv) == 0) {
		error = dsl_dataset_rollback(name, tgt, zvol_tag(zv), outnvl);
		zvol_resume(zv);
	} else {
		error = dsl_dataset_rollback(name, tgt, NULL, outnvl);
	}
	nvlist_free(outnvl);
	return (error);
}

static int
zfshandle_op_derive(zfshandle_t *zh, struct zfd_derive_args *args,
    struct thread *td)
{
	zfshandle_t *nzh;
	int error, fd;

	if ((args->zd_rights & ~ZH_ALL_RIGHTS) != 0 || args->zd_pad != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zd_rights & ~zh->zh_rights) != 0)
		return (SET_ERROR(ENOTCAPABLE));

	mutex_enter(&zh->zh_lock);
	nzh = zfshandle_alloc(zh->zh_pool_guid, zh->zh_dsobj, zh->zh_ds_guid,
	    args->zd_rights, zh->zh_flags, zh->zh_name);
	nzh->zh_ops = zh->zh_ops & ((zh->zh_flags & ZHF_POOL) != 0 ?
	    zfshandle_pool_profile(nzh->zh_rights) :
	    zfshandle_dataset_profile(nzh->zh_rights, nzh->zh_flags));
	mutex_exit(&zh->zh_lock);
	if ((zh->zh_flags & ZHF_SEND_ONCE) != 0)
		zfshandle_send_share(nzh, zh);

	error = zfshandle_install(td, nzh, &fd);
	if (error != 0)
		return (error);
	SDT_PROBE3(trustedzfs, , , derive, zh->zh_ds_guid, zh->zh_rights,
	    nzh->zh_rights);
	args->zd_fd = fd;
	return (0);
}

static int
zfshandle_op_openat(zfshandle_t *zh, struct zfd_openat_args *args,
    struct thread *td)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char full[ZFS_MAX_DATASET_NAME_LEN];
	zfshandle_t *nzh;
	objset_t *os;
	dsl_dataset_t *ds;
	uint64_t dsobj, ds_guid;
	uint32_t flags;
	int error, fd;

	if (zfshandle_str_validate(args->zo_relname,
	    sizeof (args->zo_relname), B_TRUE) != 0 ||
	    zfshandle_relpath_validate(args->zo_relname) != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zo_rights & ~ZH_ALL_RIGHTS) != 0)
		return (SET_ERROR(EINVAL));
	error = zfshandle_child_flags(zh, args->zo_flags, &flags);
	if (error != 0)
		return (error);
	if ((args->zo_rights & ~zh->zh_rights) != 0)
		return (SET_ERROR(ENOTCAPABLE));
	/* Descending needs a subtree grant; "@snap" of self does not. */
	if (args->zo_relname[0] != '@' && (zh->zh_flags & ZHF_SUBTREE) == 0)
		return (SET_ERROR(ENOTCAPABLE));

	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	if (snprintf(full, sizeof (full), "%s%s%s", name,
	    args->zo_relname[0] == '@' ? "" : "/", args->zo_relname) >=
	    (int)sizeof (full))
		return (SET_ERROR(ENAMETOOLONG));
	if (entity_namecheck(full, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));

	error = dmu_objset_hold(full, FTAG, &os);
	if (error != 0)
		return (error);
	ds = dmu_objset_ds(os);
	dsobj = ds->ds_object;
	ds_guid = dsl_dataset_phys(ds)->ds_guid;
	if (spa_guid(dmu_objset_spa(os)) != zh->zh_pool_guid) {
		dmu_objset_rele(os, FTAG);
		return (SET_ERROR(ENXIO));
	}
	dmu_objset_rele(os, FTAG);

	nzh = zfshandle_alloc(zh->zh_pool_guid, dsobj, ds_guid,
	    args->zo_rights, flags, full);
	nzh->zh_ops &= zh->zh_ops;
	if ((zh->zh_flags & ZHF_SEND_ONCE) != 0)
		zfshandle_send_share(nzh, zh);
	error = zfshandle_install(td, nzh, &fd);
	if (error != 0)
		return (error);
	SDT_PROBE4(trustedzfs, , , handle__openat, zh->zh_ds_guid,
	    nzh->zh_name, ds_guid, nzh->zh_rights);
	args->zo_fd = fd;
	return (0);
}

/*
 * Phase 2 verbs are implemented by driving the upstream vectored ioctl
 * dispatch in-kernel via FKIOCTL (nvlists and name in kernel memory).  This
 * reuses upstream semantics (unmount handling, feature checks, history
 * logging) without duplicating any of it.
 *
 * The handle's rights mask is the authorization; the ambient secpolicy that
 * zfsdev_ioctl_common runs would re-check the caller's cred, so the call is
 * made with the kernel cred (thread0's) temporarily installed on the thread.
 * Rights were verified against the handle before this point.  Jail dataset
 * visibility still applies (it checks curproc, not the thread cred) — a
 * jailed holder remains confined to jail-visible datasets in Phase 2.
 */
static cred_t *
zfshandle_cred_enter(void)
{
	struct thread *td = curthread;
	cred_t *saved = td->td_ucred;

	crhold(kcred);
	td->td_ucred = kcred;
	return (saved);
}

static void
zfshandle_cred_exit(cred_t *saved)
{
	struct thread *td = curthread;

	td->td_ucred = saved;
	crfree(kcred);
}

static int
zfshandle_ioc_flags(uint64_t ioc, const char *name, const char *value,
    uint64_t cookie, uint64_t zflags, nvlist_t *innvl, nvlist_t **outnvlp)
{
	const size_t dstlen = 128 * 1024;
	zfs_cmd_t *zc;
	char *packed = NULL, *dst = NULL;
	size_t plen = 0;
	cred_t *saved;
	int error;

	zc = vmem_zalloc(sizeof (*zc), KM_SLEEP);
	(void) strlcpy(zc->zc_name, name, sizeof (zc->zc_name));
	if (value != NULL)
		(void) strlcpy(zc->zc_value, value, sizeof (zc->zc_value));
	zc->zc_cookie = cookie;
	zc->zc_flags = zflags;
	if (innvl != NULL) {
		packed = fnvlist_pack(innvl, &plen);
		zc->zc_nvlist_src = (uintptr_t)packed;
		zc->zc_nvlist_src_size = plen;
	}
	if (outnvlp != NULL) {
		dst = vmem_alloc(dstlen, KM_SLEEP);
		zc->zc_nvlist_dst = (uintptr_t)dst;
		zc->zc_nvlist_dst_size = dstlen;
	}

	saved = zfshandle_cred_enter();
	error = zfsdev_ioctl_common(ioc - ZFS_IOC_FIRST, zc, FKIOCTL);
	zfshandle_cred_exit(saved);

	if (error == 0 && outnvlp != NULL && zc->zc_nvlist_dst_filled)
		*outnvlp = fnvlist_unpack(dst, zc->zc_nvlist_dst_size);

	if (packed != NULL)
		fnvlist_pack_free(packed, plen);
	if (dst != NULL)
		vmem_free(dst, dstlen);
	vmem_free(zc, sizeof (*zc));
	return (error);
}

static int
zfshandle_ioc(uint64_t ioc, const char *name, const char *value,
    uint64_t cookie, nvlist_t *innvl, nvlist_t **outnvlp)
{
	return (zfshandle_ioc_flags(ioc, name, value, cookie, 0, innvl,
	    outnvlp));
}

/*
 * Compose <handle's current name> + relative child name, with the same
 * containment rules as ZFD_OPENAT.  relname "" resolves to the handle
 * itself when allow_self is set.
 */
static int
zfshandle_relname(zfshandle_t *zh, const char *relname, boolean_t allow_self,
    char *full, size_t fulllen)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	if (relname[0] == '\0') {
		if (!allow_self)
			return (SET_ERROR(EINVAL));
		return (zfshandle_resolve_name(zh, full, fulllen));
	}
	if (zfshandle_relpath_validate(relname) != 0)
		return (SET_ERROR(EINVAL));
	if (relname[0] != '@' && (zh->zh_flags & ZHF_SUBTREE) == 0)
		return (SET_ERROR(ENOTCAPABLE));

	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	if (snprintf(full, fulllen, "%s%s%s", name,
	    relname[0] == '@' ? "" : "/", relname) >= (int)fulllen)
		return (SET_ERROR(ENAMETOOLONG));
	if (entity_namecheck(full, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	return (0);
}

/* Mint a handle for a dataset by full name and install it as an fd. */
static int
zfshandle_mint_child(struct thread *td, zfshandle_t *zh, const char *full,
    uint64_t rights, uint32_t flags, int32_t *fdp)
{
	zfshandle_t *nzh;
	objset_t *os;
	dsl_dataset_t *ds;
	uint64_t dsobj, ds_guid;
	uint32_t child_flags;
	int error, fd;

	error = zfshandle_child_flags(zh, flags, &child_flags);
	if (error != 0)
		return (error);

	error = dmu_objset_hold(full, FTAG, &os);
	if (error != 0)
		return (error);
	ds = dmu_objset_ds(os);
	dsobj = ds->ds_object;
	ds_guid = dsl_dataset_phys(ds)->ds_guid;
	if (spa_guid(dmu_objset_spa(os)) != zh->zh_pool_guid) {
		dmu_objset_rele(os, FTAG);
		return (SET_ERROR(ENXIO));
	}
	dmu_objset_rele(os, FTAG);

	nzh = zfshandle_alloc(zh->zh_pool_guid, dsobj, ds_guid, rights,
	    child_flags, full);
	if ((zh->zh_flags & ZHF_POOL) == 0)
		nzh->zh_ops &= zh->zh_ops;
	if ((zh->zh_flags & ZHF_SEND_ONCE) != 0)
		zfshandle_send_share(nzh, zh);
	error = zfshandle_install(td, nzh, &fd);
	if (error != 0)
		return (error);
	SDT_PROBE4(trustedzfs, , , handle__openat, zh->zh_ds_guid, full,
	    ds_guid, rights | ZH_IMPLICIT_RIGHTS);
	*fdp = fd;
	return (0);
}

static int
zfshandle_op_create(zfshandle_t *zh, struct zfd_create_args *args,
    struct thread *td)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl, *props;
	int error;

	if (zfshandle_str_validate(args->zc_relname,
	    sizeof (args->zc_relname), B_TRUE) != 0 ||
	    strchr(args->zc_relname, '@') != NULL)
		return (SET_ERROR(EINVAL));
	if (args->zc_type != ZFD_TYPE_FILESYSTEM &&
	    args->zc_type != ZFD_TYPE_VOLUME)
		return (SET_ERROR(EINVAL));
	if (args->zc_pad != 0 ||
	    zfshandle_flags_validate(args->zc_handle_flags) != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zc_type == ZFD_TYPE_FILESYSTEM &&
	    (args->zc_volsize != 0 || args->zc_volblocksize != 0)) ||
	    (args->zc_type == ZFD_TYPE_VOLUME && args->zc_volsize == 0))
		return (SET_ERROR(EINVAL));

	error = zfshandle_relname(zh, args->zc_relname, B_FALSE, full,
	    sizeof (full));
	if (error != 0)
		return (error);

	innvl = fnvlist_alloc();
	fnvlist_add_int32(innvl, "type",
	    args->zc_type == ZFD_TYPE_VOLUME ? DMU_OST_ZVOL : DMU_OST_ZFS);
	if (args->zc_type == ZFD_TYPE_VOLUME) {
		props = fnvlist_alloc();
		fnvlist_add_uint64(props, "volsize", args->zc_volsize);
		if (args->zc_volblocksize != 0)
			fnvlist_add_uint64(props, "volblocksize",
			    args->zc_volblocksize);
		fnvlist_add_nvlist(innvl, "props", props);
		nvlist_free(props);
	}
	error = zfshandle_ioc(ZFS_IOC_CREATE, full, NULL, 0, innvl, NULL);
	nvlist_free(innvl);
	if (error != 0)
		return (error);

	error = zfshandle_mint_child(td, zh, full, zh->zh_rights,
	    args->zc_handle_flags, &args->zc_fd);
	if (error != 0)
		(void) zfshandle_ioc(ZFS_IOC_DESTROY, full, NULL, 0, NULL, NULL);
	return (error);
}

static int
zfshandle_op_destroy(zfshandle_t *zh, struct zfd_destroy_args *args,
    struct ucred *cred)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	if (zfshandle_str_validate(args->zd_relname,
	    sizeof (args->zd_relname), B_FALSE) != 0 ||
	    strchr(args->zd_relname, '@') != NULL)
		return (SET_ERROR(EINVAL));
	error = zfshandle_relname(zh, args->zd_relname, B_TRUE, full,
	    sizeof (full));
	if (error != 0)
		return (error);
#ifdef MAC
	error = mac_zfs_check_dataset_destroy(cred, full);
	if (error != 0)
		return (error);
#endif
	return (zfshandle_ioc(ZFS_IOC_DESTROY, full, NULL, 0, NULL, NULL));
}

static int
zfshandle_op_rename(zfshandle_t *zh, struct zfd_rename_args *args)
{
	char from[ZFS_MAX_DATASET_NAME_LEN];
	char to[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	if (zfshandle_str_validate(args->zr_from,
	    sizeof (args->zr_from), B_FALSE) != 0 ||
	    zfshandle_str_validate(args->zr_to,
	    sizeof (args->zr_to), B_TRUE) != 0 ||
	    strchr(args->zr_to, '@') != NULL ||
	    strchr(args->zr_from, '@') != NULL)
		return (SET_ERROR(EINVAL));
	error = zfshandle_relname(zh, args->zr_from, B_TRUE, from,
	    sizeof (from));
	if (error != 0)
		return (error);
	/*
	 * The destination is always relative to the handle: renaming self
	 * still cannot move the dataset out of the grant.
	 */
	if (args->zr_from[0] == '\0' && (zh->zh_flags & ZHF_SUBTREE) == 0) {
		/*
		 * Self-rename on a non-subtree handle: the new name replaces
		 * the last component of the current name.
		 */
		char *slash = strrchr(from, '/');

		if (slash == NULL)
			return (SET_ERROR(EINVAL));
		if (snprintf(to, sizeof (to), "%.*s/%s",
		    (int)(slash - from), from, args->zr_to) >=
		    (int)sizeof (to))
			return (SET_ERROR(ENAMETOOLONG));
		if (entity_namecheck(to, NULL, NULL) != 0)
			return (SET_ERROR(EINVAL));
	} else {
		error = zfshandle_relname(zh, args->zr_to, B_FALSE, to,
		    sizeof (to));
		if (error != 0)
			return (error);
	}
	return (zfshandle_ioc(ZFS_IOC_RENAME, from, to, 0, NULL, NULL));
}

static int
zfshandle_op_clone(zfshandle_t *zh, struct zfd_clone_args *args,
    struct thread *td)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char origin[ZFS_MAX_DATASET_NAME_LEN];
	zfshandle_t *ozh;
	struct file *ofp;
	nvlist_t *innvl;
	int error;

	if (zfshandle_str_validate(args->zc_relname,
	    sizeof (args->zc_relname), B_TRUE) != 0 ||
	    zfshandle_str_validate(args->zc_origin_snap,
	    sizeof (args->zc_origin_snap), B_FALSE) != 0 ||
	    strchr(args->zc_relname, '@') != NULL)
		return (SET_ERROR(EINVAL));

	/* The two-handle step: the origin must be a handle w/ CLONE_SRC. */
	error = fget(td, args->zc_origin_fd, &cap_no_rights, &ofp);
	if (error != 0)
		return (error);
	if (ofp->f_type != DTYPE_ZFSHANDLE) {
		fdrop(ofp, td);
		return (SET_ERROR(EBADF));
	}
	ozh = ofp->f_data;
	if ((ozh->zh_rights & ZH_CLONE_SRC) == 0) {
		SDT_PROBE4(trustedzfs, , , denied, ozh->zh_ds_guid,
		    (int)ZFD_CLONE, (uint64_t)ZH_CLONE_SRC, ozh->zh_rights);
		fdrop(ofp, td);
		return (SET_ERROR(EPERM));
	}
	if ((ozh->zh_ops & ZFD_OP_CLONE_SOURCE) == 0) {
		fdrop(ofp, td);
		return (SET_ERROR(ENOTCAPABLE));
	}
	error = zfshandle_resolve_name(ozh, origin, sizeof (origin));
	if (error != 0) {
		fdrop(ofp, td);
		return (error);
	}
	fdrop(ofp, td);

	if (args->zc_origin_snap[0] != '\0') {
		char osnap[ZFS_MAX_DATASET_NAME_LEN];

		if (zfs_component_namecheck(args->zc_origin_snap, NULL,
		    NULL) != 0 || strchr(origin, '@') != NULL)
			return (SET_ERROR(EINVAL));
		if (snprintf(osnap, sizeof (osnap), "%s@%s", origin,
		    args->zc_origin_snap) >= (int)sizeof (osnap))
			return (SET_ERROR(ENAMETOOLONG));
		(void) strlcpy(origin, osnap, sizeof (origin));
	} else if (strchr(origin, '@') == NULL) {
		return (SET_ERROR(EINVAL));
	}

	error = zfshandle_relname(zh, args->zc_relname, B_FALSE, full,
	    sizeof (full));
	if (error != 0)
		return (error);

	innvl = fnvlist_alloc();
	fnvlist_add_string(innvl, "origin", origin);
	error = zfshandle_ioc(ZFS_IOC_CLONE, full, NULL, 0, innvl, NULL);
	nvlist_free(innvl);
	if (error != 0)
		return (error);

	error = zfshandle_mint_child(td, zh, full, zh->zh_rights, 0,
	    &args->zc_fd);
	if (error != 0)
		(void) zfshandle_ioc(ZFS_IOC_DESTROY, full, NULL, 0, NULL, NULL);
	return (error);
}

/* Compose the full snapshot name for stream/hold verbs. */
static int
zfshandle_snapref(zfshandle_t *zh, const char *component, char *full,
    size_t fulllen)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	if (component[0] == '\0') {
		if (strchr(name, '@') == NULL)
			return (SET_ERROR(EINVAL));
		(void) strlcpy(full, name, fulllen);
		return (0);
	}
	if (strchr(name, '@') != NULL ||
	    zfs_component_namecheck(component, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	if (snprintf(full, fulllen, "%s@%s", name, component) >=
	    (int)fulllen)
		return (SET_ERROR(ENAMETOOLONG));
	return (0);
}

static int
zfshandle_send_begin(zfshandle_t *zh)
{
	zfshandle_send_state_t *zss;
	int error;

	if ((zh->zh_flags & ZHF_SEND_ONCE) == 0)
		return (0);
	zss = zh->zh_send;
	mutex_enter(&zss->zss_lock);
	switch (zss->zss_status) {
	case ZH_SEND_READY:
		zss->zss_status = ZH_SEND_RUNNING;
		error = 0;
		break;
	case ZH_SEND_RUNNING:
		error = SET_ERROR(EBUSY);
		break;
	default:
		error = SET_ERROR(EALREADY);
		break;
	}
	mutex_exit(&zss->zss_lock);
	return (error);
}

static void
zfshandle_send_finish(zfshandle_t *zh, int error)
{
	zfshandle_send_state_t *zss;
	zfshandle_t *iter;

	if ((zh->zh_flags & ZHF_SEND_ONCE) == 0)
		return;
	zss = zh->zh_send;
	mutex_enter(&zss->zss_lock);
	if (error != 0) {
		zss->zss_status = ZH_SEND_READY;
		mutex_exit(&zss->zss_lock);
		return;
	}
	zss->zss_status = ZH_SEND_SPENT;
	if ((zh->zh_flags & ZHF_SEND_CONSUME) != 0) {
		zss->zss_consumed = B_TRUE;
		TAILQ_FOREACH(iter, &zss->zss_handles, zh_send_link)
			zfshandle_invalidate(iter, ZH_INVAL_DESTROYED);
	}
	mutex_exit(&zss->zss_lock);
}

static int
zfshandle_op_send(zfshandle_t *zh, struct zfd_send_args *args,
    struct ucred *cred)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char from[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl;
	int error;

	if (zfshandle_str_validate(args->zs_snapname,
	    sizeof (args->zs_snapname), B_FALSE) != 0 ||
	    zfshandle_str_validate(args->zs_fromsnap,
	    sizeof (args->zs_fromsnap), B_FALSE) != 0 ||
	    (args->zs_flags & ~ZFD_SEND_ALL) != 0)
		return (SET_ERROR(EINVAL));

	error = zfshandle_snapref(zh, args->zs_snapname, full,
	    sizeof (full));
	if (error != 0)
		return (error);
#ifdef MAC
	error = mac_zfs_check_send(cred, full);
	if (error != 0)
		return (error);
#endif

	innvl = fnvlist_alloc();
	fnvlist_add_int32(innvl, "fd", args->zs_out_fd);
	if (args->zs_fromsnap[0] != '\0') {
		char *at = strchr(full, '@');

		if (zfs_component_namecheck(args->zs_fromsnap, NULL,
		    NULL) != 0 || at == NULL ||
		    snprintf(from, sizeof (from), "%.*s@%s",
		    (int)(at - full), full, args->zs_fromsnap) >=
		    (int)sizeof (from)) {
			nvlist_free(innvl);
			return (SET_ERROR(EINVAL));
		}
		fnvlist_add_string(innvl, "fromsnap", from);
	}
	if (args->zs_flags & ZFD_SEND_EMBED)
		fnvlist_add_boolean(innvl, "embedok");
	if (args->zs_flags & ZFD_SEND_LARGEBLOCK)
		fnvlist_add_boolean(innvl, "largeblockok");
	if (args->zs_flags & ZFD_SEND_COMPRESS)
		fnvlist_add_boolean(innvl, "compressok");
	if (args->zs_flags & ZFD_SEND_RAW)
		fnvlist_add_boolean(innvl, "rawok");

	error = zfshandle_send_begin(zh);
	if (error != 0) {
		nvlist_free(innvl);
		return (error);
	}
	error = zfshandle_ioc(ZFS_IOC_SEND_NEW, full, NULL, 0, innvl, NULL);
	nvlist_free(innvl);
	zfshandle_send_finish(zh, error);
	return (error);
}

static int
zfshandle_op_recv(zfshandle_t *zh, struct zfd_recv_args *args,
    struct ucred *cred)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char fsname[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl;
	char *at;
	int error;

	if (zfshandle_str_validate(args->zr_reltarget,
	    sizeof (args->zr_reltarget), B_TRUE) != 0 || args->zr_force > 1 ||
	    strchr(args->zr_reltarget, '@') == NULL)
		return (SET_ERROR(EINVAL));
	error = zfshandle_relname(zh, args->zr_reltarget, B_FALSE, full,
	    sizeof (full));
	if (error != 0)
		return (error);
	(void) strlcpy(fsname, full, sizeof (fsname));
	at = strchr(fsname, '@');
	*at = '\0';
#ifdef MAC
	error = mac_zfs_check_receive(cred, fsname);
	if (error != 0)
		return (error);
#endif

	innvl = fnvlist_alloc();
	fnvlist_add_string(innvl, "snapname", full);
	fnvlist_add_byte_array(innvl, "begin_record",
	    args->zr_begin_record, ZFD_BEGIN_RECORD_SIZE);
	fnvlist_add_int32(innvl, "input_fd", args->zr_input_fd);
	if (args->zr_force)
		fnvlist_add_boolean(innvl, "force");

	error = zfshandle_ioc(ZFS_IOC_RECV_NEW, fsname, NULL, 0, innvl,
	    NULL);
	nvlist_free(innvl);
	return (error);
}

static int
zfshandle_op_hold(zfshandle_t *zh, struct zfd_hold_args *args,
    boolean_t hold)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char pool[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl, *holds;
	char *slash;
	int error;

	if (zfshandle_str_validate(args->zh_snapname,
	    sizeof (args->zh_snapname), B_FALSE) != 0 ||
	    zfshandle_str_validate(args->zh_tag,
	    sizeof (args->zh_tag), B_TRUE) != 0)
		return (SET_ERROR(EINVAL));
	if (args->zh_tag[0] == '\0')
		return (SET_ERROR(EINVAL));
	error = zfshandle_snapref(zh, args->zh_snapname, full,
	    sizeof (full));
	if (error != 0)
		return (error);
	(void) strlcpy(pool, full, sizeof (pool));
	if ((slash = strchr(pool, '/')) != NULL)
		*slash = '\0';
	else if ((slash = strchr(pool, '@')) != NULL)
		*slash = '\0';

	if (hold) {
		holds = fnvlist_alloc();
		fnvlist_add_string(holds, full, args->zh_tag);
		innvl = fnvlist_alloc();
		fnvlist_add_nvlist(innvl, "holds", holds);
		nvlist_free(holds);
		error = zfshandle_ioc(ZFS_IOC_HOLD, pool, NULL, 0, innvl,
		    NULL);
	} else {
		nvlist_t *tags = fnvlist_alloc();

		fnvlist_add_boolean(tags, args->zh_tag);
		innvl = fnvlist_alloc();
		fnvlist_add_nvlist(innvl, full, tags);
		nvlist_free(tags);
		error = zfshandle_ioc(ZFS_IOC_RELEASE, pool, NULL, 0, innvl,
		    NULL);
	}
	nvlist_free(innvl);
	return (error);
}

/* Pack a bounded nvlist into the caller's GET_PROPS-style buffer and free it. */
static int
zfshandle_nvl_copyout(nvlist_t *nv, struct zfd_get_props_args *args)
{
	nvpair_t *elem;
	char *packed;
	size_t size;
	uint64_t entries;
	int error;

	args->zgp_size = 0;
	entries = 0;
	for (elem = nvlist_next_nvpair(nv, NULL); elem != NULL;
	    elem = nvlist_next_nvpair(nv, elem)) {
		if (++entries > (uint64_t)zfshandle_enum_max_entries) {
			nvlist_free(nv);
			return (SET_ERROR(E2BIG));
		}
	}
	packed = fnvlist_pack(nv, &size);
	nvlist_free(nv);
	args->zgp_size = size;
	if (size > ZH_NVLIST_MAX)
		error = SET_ERROR(E2BIG);
	else if (args->zgp_buflen < size)
		error = SET_ERROR(ENOMEM);
	else
		error = copyout(packed, (void *)(uintptr_t)args->zgp_buf,
		    size);
	fnvlist_pack_free(packed, size);
	return (error);
}

/*
 * Enumerate children (want_snaps == B_FALSE) or snapshots (B_TRUE) of the
 * handle's dataset into a name-set nvlist.  The kernel walks the whole set
 * so userland needs no cursor; each key is the full child/snapshot name.
 */
static int
zfshandle_op_list(zfshandle_t *zh, struct zfd_get_props_args *args,
    boolean_t want_snaps)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char child[ZFS_MAX_DATASET_NAME_LEN];
	char full[ZFS_MAX_DATASET_NAME_LEN];
	objset_t *os;
	nvlist_t *nv;
	uint64_t cookie, id, entries;
	int error, len;

	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	error = dmu_objset_hold(name, FTAG, &os);
	if (error != 0)
		return (error);

	nv = fnvlist_alloc();
	cookie = 0;
	entries = 0;
	for (;;) {
		if (want_snaps)
			error = dmu_snapshot_list_next(os,
			    sizeof (child), child, &id, &cookie, NULL);
		else
			error = dmu_dir_list_next(os,
			    sizeof (child), child, &id, &cookie);
		if (error == ENOENT) {
			error = 0;
			break;
		}
		if (error != 0)
			break;
		if (++entries > (uint64_t)zfshandle_enum_max_entries) {
			error = SET_ERROR(E2BIG);
			break;
		}
		len = snprintf(full, sizeof (full), "%s%c%s", name,
		    want_snaps ? '@' : '/', child);
		if (len < (int)sizeof (full))
			fnvlist_add_boolean(nv, full);
	}
	dmu_objset_rele(os, FTAG);
	if (error != 0) {
		nvlist_free(nv);
		return (error);
	}
	return (zfshandle_nvl_copyout(nv, args));
}

static int
zfshandle_op_get_one_prop(zfshandle_t *zh, struct zfd_get_one_prop_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char setpoint[ZFS_MAX_DATASET_NAME_LEN];
	zfs_prop_t prop;
	int error;

	if (zfshandle_str_validate(args->zgo_name,
	    sizeof (args->zgo_name), B_TRUE) != 0)
		return (SET_ERROR(EINVAL));
	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);

	prop = zfs_name_to_prop(args->zgo_name);
	if (prop == ZPROP_USERPROP) {
		/*
		 * User property (or unknown): these exist only when set, so
		 * the get-all nvlist is authoritative.
		 */
		objset_t *os;
		nvlist_t *nv, *propval;
		const char *strval;
		dsl_pool_t *dp;
		dsl_dataset_t *ds;

		error = zfshandle_hold(zh, FTAG, &dp, &ds);
		if (error != 0)
			return (error);
		error = dmu_objset_from_ds(ds, &os);
		if (error == 0)
			error = dsl_prop_get_all(os, &nv);
		zfshandle_rele(dp, ds, FTAG);
		if (error != 0)
			return (error);
		if (nvlist_lookup_nvlist(nv, args->zgo_name, &propval) != 0 ||
		    nvlist_lookup_string(propval, ZPROP_VALUE, &strval) != 0) {
			nvlist_free(nv);
			return (SET_ERROR(ENOENT));
		}
		(void) strlcpy(args->zgo_strval, strval,
		    sizeof (args->zgo_strval));
		args->zgo_is_string = 1;
		args->zgo_source = ZPROP_SRC_LOCAL;
		nvlist_free(nv);
		return (0);
	}

	/* Native property: resolves even at its default value. */
	setpoint[0] = '\0';
	if (zfs_prop_get_type(prop) == PROP_TYPE_STRING) {
		error = dsl_prop_get(name, args->zgo_name, 1,
		    sizeof (args->zgo_strval), args->zgo_strval, setpoint);
		if (error != 0)
			return (error);
		args->zgo_is_string = 1;
	} else {
		error = dsl_prop_get_integer(name, args->zgo_name,
		    &args->zgo_intval, setpoint);
		if (error != 0)
			return (error);
		args->zgo_is_string = 0;
	}
	args->zgo_source = setpoint[0] == '\0' ? ZPROP_SRC_DEFAULT :
	    (strcmp(setpoint, name) == 0 ? ZPROP_SRC_LOCAL :
	    ZPROP_SRC_INHERITED);
	return (0);
}

static int
zfshandle_op_holds(zfshandle_t *zh, struct zfd_get_props_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *nv;
	int error;

	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	if (strchr(name, '@') == NULL)
		return (SET_ERROR(EINVAL));	/* holds are on snapshots */
	nv = fnvlist_alloc();
	error = dsl_dataset_get_holds(name, nv);
	if (error != 0) {
		nvlist_free(nv);
		return (error);
	}
	return (zfshandle_nvl_copyout(nv, args));
}

static int
zfshandle_op_inherit(zfshandle_t *zh, struct zfd_inherit_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	if (zfshandle_str_validate(args->zin_name,
	    sizeof (args->zin_name), B_TRUE) != 0 ||
	    args->zin_received > 1 || args->zin_pad != 0)
		return (SET_ERROR(EINVAL));
	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	return (dsl_prop_inherit(name, args->zin_name,
	    args->zin_received ? ZPROP_SRC_NONE : ZPROP_SRC_INHERITED));
}

static int
zfshandle_op_promote(zfshandle_t *zh)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char conflict[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	conflict[0] = '\0';
	return (dsl_dataset_promote(name, conflict));
}

/* Compose "<fs>#<bookmark>" from a bookmark component. */
static int
zfshandle_bookname(const char *fsname, const char *component, char *buf,
    size_t buflen)
{
	if (component[0] == '\0' ||
	    zfs_component_namecheck(component, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	if (snprintf(buf, buflen, "%s#%s", fsname, component) >= (int)buflen)
		return (SET_ERROR(ENAMETOOLONG));
	return (0);
}

static int
zfshandle_op_bookmark(zfshandle_t *zh, struct zfd_bookmark_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char snap[ZFS_MAX_DATASET_NAME_LEN];
	char book[ZFS_MAX_DATASET_NAME_LEN];
	char pool[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl;
	char *slash;
	int error;

	if (zfshandle_str_validate(args->zbm_snapname,
	    sizeof (args->zbm_snapname), B_FALSE) != 0 ||
	    zfshandle_str_validate(args->zbm_bookname,
	    sizeof (args->zbm_bookname), B_TRUE) != 0)
		return (SET_ERROR(EINVAL));
	error = zfshandle_snapref(zh, args->zbm_snapname, snap,
	    sizeof (snap));
	if (error != 0)
		return (error);
	/* The bookmark lives on the snapshot's filesystem. */
	(void) strlcpy(name, snap, sizeof (name));
	*strchr(name, '@') = '\0';
	error = zfshandle_bookname(name, args->zbm_bookname, book,
	    sizeof (book));
	if (error != 0)
		return (error);
	(void) strlcpy(pool, name, sizeof (pool));
	if ((slash = strchr(pool, '/')) != NULL)
		*slash = '\0';

	innvl = fnvlist_alloc();
	fnvlist_add_string(innvl, book, snap);
	error = zfshandle_ioc(ZFS_IOC_BOOKMARK, pool, NULL, 0, innvl, NULL);
	nvlist_free(innvl);
	return (error);
}

static int
zfshandle_op_list_bookmarks(zfshandle_t *zh, struct zfd_get_props_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char full[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl, *raw = NULL, *out;
	nvpair_t *elem;
	int error, len;

	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	if (strchr(name, '@') != NULL)
		return (SET_ERROR(EINVAL));
	innvl = fnvlist_alloc();		/* no props requested: names only */
	error = zfshandle_ioc(ZFS_IOC_GET_BOOKMARKS, name, NULL, 0, innvl,
	    &raw);
	nvlist_free(innvl);
	if (error != 0)
		return (error);

	/*
	 * The ioctl keys results by short bookmark name; rewrite to full
	 * "fs#bookmark" names to match ZFD_LIST_SNAPS / ZFD_LIST_CHILDREN.
	 */
	out = fnvlist_alloc();
	if (raw != NULL) {
		for (elem = nvlist_next_nvpair(raw, NULL); elem != NULL;
		    elem = nvlist_next_nvpair(raw, elem)) {
			len = snprintf(full, sizeof (full), "%s#%s", name,
			    nvpair_name(elem));
			if (len < (int)sizeof (full))
				fnvlist_add_boolean(out, full);
		}
		nvlist_free(raw);
	}
	return (zfshandle_nvl_copyout(out, args));
}

static int
zfshandle_op_destroy_bookmark(zfshandle_t *zh, struct zfd_bookmark_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char book[ZFS_MAX_DATASET_NAME_LEN];
	char pool[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl;
	char *slash;
	int error;

	if (zfshandle_str_validate(args->zbm_snapname,
	    sizeof (args->zbm_snapname), B_FALSE) != 0 ||
	    zfshandle_str_validate(args->zbm_bookname,
	    sizeof (args->zbm_bookname), B_TRUE) != 0 ||
	    args->zbm_snapname[0] != '\0')
		return (SET_ERROR(EINVAL));
	error = zfshandle_resolve_name(zh, name, sizeof (name));
	if (error != 0)
		return (error);
	if (strchr(name, '@') != NULL)
		return (SET_ERROR(EINVAL));
	error = zfshandle_bookname(name, args->zbm_bookname, book,
	    sizeof (book));
	if (error != 0)
		return (error);
	(void) strlcpy(pool, name, sizeof (pool));
	if ((slash = strchr(pool, '/')) != NULL)
		*slash = '\0';

	innvl = fnvlist_alloc();
	fnvlist_add_boolean(innvl, book);
	error = zfshandle_ioc(ZFS_IOC_DESTROY_BOOKMARKS, pool, NULL, 0,
	    innvl, NULL);
	nvlist_free(innvl);
	return (error);
}

/*
 * zvol data-plane bridge: open /dev/zvol/<name> kernel-side and install
 * the resulting vnode fd.  The lookup runs with the caller's thread, so
 * this returns ECAPMODE in capability mode for now — consumers resolve
 * before cap_enter() (bhyve's disk-open model).  Phase 3 replaces the
 * path walk with direct devfs-vnode plumbing.
 */
static int
zfshandle_op_blkopen(zfshandle_t *zh, struct zfd_blkopen_args *args,
    struct thread *td)
{
	char path[MAXPATHLEN];
	char name[ZFS_MAX_DATASET_NAME_LEN];
	struct nameidata nd;
	struct file *fp;
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	objset_t *os;
	int error, fd, flags;

	if (args->zb_write > 1)
		return (SET_ERROR(EINVAL));

	/* The dataset must be a volume. */
	error = zfshandle_hold(zh, FTAG, &dp, &ds);
	if (error != 0)
		return (error);
	error = dmu_objset_from_ds(ds, &os);
	if (error == 0 && dmu_objset_type(os) != DMU_OST_ZVOL)
		error = SET_ERROR(ENOTBLK);
	dsl_dataset_name(ds, name);
	zfshandle_rele(dp, ds, FTAG);
	if (error != 0)
		return (error);

	if (snprintf(path, sizeof (path), "/dev/zvol/%s", name) >=
	    (int)sizeof (path))
		return (SET_ERROR(ENAMETOOLONG));

	error = falloc_noinstall(td, &fp);
	if (error != 0)
		return (error);
	flags = FREAD | (args->zb_write ? FWRITE : 0);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, path);
	error = vn_open(&nd, &flags, 0, fp);
	if (error != 0) {
		fdrop(fp, td);
		return (error);
	}
	NDFREE_PNBUF(&nd);
	fp->f_flag = flags & FMASK;
	if (fp->f_ops == &badfileops)
		finit_vnode(fp, flags, NULL, &vnops);
	VOP_UNLOCK(nd.ni_vp);

	error = finstall(td, fp, &fd, flags | O_CLOEXEC, NULL);
	fdrop(fp, td);
	if (error != 0)
		return (error);
	args->zb_fd = fd;
	return (0);
}

/*
 * Anonymous mount machinery.  This is vfs_domount_first() minus the two
 * namespace-attach steps (covered vnode / v_mountedhere): the mount is
 * instantiated, placed on mountlist (so fsid lookup, the syncer, and
 * shutdown's unmount-all see it), but is unreachable by path lookup —
 * its root dirfd is the only way in.  mnt_vnodecovered stays NULL, a
 * state the VFS already supports for the root mount.
 */
static int
zfshandle_anon_mount(struct thread *td, const char *osname,
    boolean_t rdonly, struct mount **mpp)
{
	struct uio auio;
	struct iovec iov[6];
	struct vfsoptlist *opts;
	struct vfsconf *vfsp;
	struct mount *mp;
	cred_t *saved_cred;
	int error, niov;
	static const char fstype[] = "zfs";
	static const char fspath[] = "[anon]";
	static const char ro[] = "ro";

	vfsp = vfs_byname_kld(fstype, td, &error);
	if (vfsp == NULL)
		return (error != 0 ? error : SET_ERROR(ENODEV));

	/* nmount-style option list: name/value string pairs. */
	niov = 0;
#define	ZH_OPT(name, val)						\
	do {								\
		iov[niov].iov_base = __DECONST(char *, (name));		\
		iov[niov].iov_len = strlen(name) + 1;			\
		niov++;							\
		iov[niov].iov_base = __DECONST(char *, (val));		\
		iov[niov].iov_len = strlen(val) + 1;			\
		niov++;							\
	} while (0)
	ZH_OPT("from", osname);
	ZH_OPT("fspath", fspath);
	if (rdonly)
		ZH_OPT(ro, "");
#undef ZH_OPT
	memset(&auio, 0, sizeof (auio));
	auio.uio_iov = iov;
	auio.uio_iovcnt = niov;
	auio.uio_segflg = UIO_SYSSPACE;
	error = vfs_buildopts(&auio, &opts);
	if (error != 0)
		return (error);

	/*
	 * ZFD_MOUNT verified ZH_MOUNT on the handle before dispatching here, so
	 * the capability — not the caller's uid — is the authorization.  Install
	 * the kernel cred across mount allocation and VFS_MOUNT so the ambient
	 * secpolicy_fs_mount() re-check (which reads curthread's cred) does not
	 * reject an unprivileged capability holder; the mount is thus root-owned
	 * exactly as a serviced-initiated mount was.  The dir fd opened below
	 * still uses the caller's restored cred.
	 */
	saved_cred = zfshandle_cred_enter();
	mp = vfs_mount_alloc(NULL, vfsp, fspath, curthread->td_ucred);
	mp->mnt_optnew = opts;
	if (rdonly)
		mp->mnt_flag |= MNT_RDONLY;

	error = VFS_MOUNT(mp);
	zfshandle_cred_exit(saved_cred);
	if (error != 0) {
		vfs_freeopts(mp->mnt_optnew);
		mp->mnt_optnew = NULL;
		vfs_unbusy(mp);		/* vfs_mount_alloc busies the mount */
		vfs_mount_destroy(mp);
		return (error);
	}
	(void) VFS_STATFS(mp, &mp->mnt_stat);

	if (mp->mnt_opt != NULL)
		vfs_freeopts(mp->mnt_opt);
	mp->mnt_opt = mp->mnt_optnew;
	mp->mnt_optnew = NULL;

	MNT_ILOCK(mp);
	if ((mp->mnt_flag & MNT_ASYNC) != 0 &&
	    (mp->mnt_kern_flag & MNTK_NOASYNC) == 0)
		mp->mnt_kern_flag |= MNTK_ASYNC;
	else
		mp->mnt_kern_flag &= ~MNTK_ASYNC;
	MNT_IUNLOCK(mp);

	/*
	 * On mountlist (dounmount at shutdown requires it; the syncer and
	 * fsid lookup want it) but never attached to a covered vnode —
	 * invisible to namei by construction.
	 */
	mtx_lock(&mountlist_mtx);
	TAILQ_INSERT_TAIL(&mountlist, mp, mnt_list);
	mtx_unlock(&mountlist_mtx);
	if (!rdonly)
		vfs_allocate_syncvnode(mp);
	/*
	 * vfs_mount_alloc returns the mount busied (mnt_lockref held) and
	 * in vfs_ops mode (mnt_vfs_ops == 1).  vfs_domount_first releases
	 * BOTH once mounted (vfs_op_exit then vfs_unbusy, lines ~1315-16)
	 * and so must we: a missed unbusy makes the eventual dounmount()
	 * sleep forever on the busy drain, and a missed op_exit trips
	 * vfs_mount_destroy's MPASSERT(mnt_vfs_ops == 1) panic.  Both were
	 * found the hard way.
	 */
	vfs_op_exit(mp);
	vfs_unbusy(mp);

	*mpp = mp;
	return (0);
}

/*
 * Tear down the handle's anonymous mount, if any.  The handle holds a
 * vfs_ref taken at mount time; dounmount() consumes one reference (the
 * kern_unmount contract).  Shutdown's unmount-all can beat us to it, so
 * re-verify list membership by identity under mountlist_mtx first.
 */
static void
zfshandle_anon_unmount(zfshandle_t *zh, struct thread *td)
{
	struct mount *mp, *iter;
	boolean_t onlist;

	mutex_enter(&zh->zh_lock);
	mp = zh->zh_anon_mp;
	zh->zh_anon_mp = NULL;
	mutex_exit(&zh->zh_lock);
	if (mp == NULL)
		return;

	onlist = B_FALSE;
	mtx_lock(&mountlist_mtx);
	TAILQ_FOREACH(iter, &mountlist, mnt_list) {
		if (iter == mp) {
			onlist = B_TRUE;
			break;
		}
	}
	mtx_unlock(&mountlist_mtx);

	if (onlist)
		(void) dounmount(mp, MNT_FORCE, td);
	else
		vfs_rel(mp);
}

static int
zfshandle_op_mount(zfshandle_t *zh, struct zfd_mount_args *args,
    struct thread *td)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	struct mount *mp;
	struct vnode *vp;
	struct file *fp;
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	objset_t *os;
	int error, fd, flags;

	if (args->zm_rdonly > 1)
		return (SET_ERROR(EINVAL));

	mutex_enter(&zh->zh_lock);
	if (zh->zh_anon_mp != NULL || zh->zh_anon_mounting) {
		mutex_exit(&zh->zh_lock);
		return (SET_ERROR(EBUSY));
	}
	zh->zh_anon_mounting = B_TRUE;
	mutex_exit(&zh->zh_lock);

	/* Only ZPL filesystems mount. */
	error = zfshandle_hold(zh, FTAG, &dp, &ds);
	if (error != 0)
		goto failed;
	error = dmu_objset_from_ds(ds, &os);
	if (error == 0 && dmu_objset_type(os) != DMU_OST_ZFS)
		error = SET_ERROR(EINVAL);
	dsl_dataset_name(ds, name);
	zfshandle_rele(dp, ds, FTAG);
	if (error != 0)
		goto failed;

	error = zfshandle_anon_mount(td, name,
	    args->zm_rdonly ? B_TRUE : B_FALSE, &mp);
	if (error != 0)
		goto failed;

	error = VFS_ROOT(mp, LK_EXCLUSIVE, &vp);
	if (error != 0)
		goto unmount;

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		vput(vp);
		goto unmount;
	}
	/*
	 * Directories never open FWRITE (EISDIR); the mount's rdonly flag,
	 * not the dirfd mode, governs writability beneath it.
	 */
	flags = FREAD;
	error = vn_open_vnode(vp, flags, td->td_ucred, td, fp);
	if (error != 0) {
		fdrop(fp, td);
		vput(vp);
		goto unmount;
	}
	/* finit_open() equivalent: bind the vnode and default vnode ops. */
	fp->f_vnode = vp;
	if (fp->f_ops == &badfileops)
		finit_vnode(fp, flags, NULL, &vnops);
	fp->f_flag = flags & FMASK;
	VOP_UNLOCK(vp);

	error = finstall(td, fp, &fd, O_CLOEXEC, NULL);
	fdrop(fp, td);
	if (error != 0)
		goto unmount;

	/* The handle anchors the mount; hold the kern_unmount-style ref. */
	vfs_ref(mp);
	mutex_enter(&zh->zh_lock);
	zh->zh_anon_mp = mp;
	zh->zh_anon_mounting = B_FALSE;
	mutex_exit(&zh->zh_lock);

	SDT_PROBE3(trustedzfs, , , op__entry, zh->zh_ds_guid,
	    (int)ZFD_MOUNT, zh->zh_rights);
	args->zm_fd = fd;
	return (0);

unmount:
	vfs_ref(mp);		/* dounmount() consumes one reference */
	(void) dounmount(mp, MNT_FORCE, td);
failed:
	mutex_enter(&zh->zh_lock);
	zh->zh_anon_mounting = B_FALSE;
	mutex_exit(&zh->zh_lock);
	return (error);
}

static zfd_opset_t
zfshandle_cmd_op(u_long cmd)
{

	switch (cmd) {
	case ZFD_INFO: return (ZFD_OP_INFO);
	case ZFD_DERIVE: return (ZFD_OP_DERIVE);
	case ZFD_OPENAT: return (ZFD_OP_OPENAT);
	case ZFD_STAT: return (ZFD_OP_STAT);
	case ZFD_GET_PROPS: return (ZFD_OP_GET_PROPS);
	case ZFD_GET_ONE_PROP: return (ZFD_OP_GET_ONE_PROP);
	case ZFD_LIST_CHILDREN: return (ZFD_OP_LIST_CHILDREN);
	case ZFD_LIST_SNAPS: return (ZFD_OP_LIST_SNAPSHOTS);
	case ZFD_HOLDS: return (ZFD_OP_HOLDS);
	case ZFD_LIST_BOOKMARKS: return (ZFD_OP_LIST_BOOKMARKS);
	case ZFD_SET_PROP: return (ZFD_OP_SET_PROP);
	case ZFD_INHERIT: return (ZFD_OP_INHERIT);
	case ZFD_SNAPSHOT: return (ZFD_OP_SNAPSHOT);
	case ZFD_BOOKMARK: return (ZFD_OP_BOOKMARK);
	case ZFD_SNAP_DESTROY: return (ZFD_OP_SNAP_DESTROY);
	case ZFD_DESTROY_BOOKMARK: return (ZFD_OP_DESTROY_BOOKMARK);
	case ZFD_ROLLBACK: return (ZFD_OP_ROLLBACK);
	case ZFD_CREATE: return (ZFD_OP_CREATE);
	case ZFD_DESTROY: return (ZFD_OP_DESTROY);
	case ZFD_RENAME: return (ZFD_OP_RENAME);
	case ZFD_CLONE: return (ZFD_OP_CLONE);
	case ZFD_PROMOTE: return (ZFD_OP_PROMOTE);
	case ZFD_SEND: return (ZFD_OP_SEND);
	case ZFD_RECV: return (ZFD_OP_RECV);
	case ZFD_HOLD: return (ZFD_OP_HOLD);
	case ZFD_RELEASE: return (ZFD_OP_RELEASE);
	case ZFD_BLKOPEN: return (ZFD_OP_BLKOPEN);
	case ZFD_MOUNT: return (ZFD_OP_MOUNT);
	case ZFD_UNMOUNT: return (ZFD_OP_UNMOUNT);
	case ZPD_STAT: return (ZFD_OP_POOL_STAT);
	case ZPD_GET_PROPS: return (ZFD_OP_POOL_GET_PROPS);
	case ZPD_SET_PROP: return (ZFD_OP_POOL_SET_PROP);
	case ZPD_SCRUB: return (ZFD_OP_POOL_SCRUB);
	case ZPD_ROOT_OPEN: return (ZFD_OP_POOL_ROOT_OPEN);
	default: return (0);
	}
}

/* Immutable authority is reported before a narrower operation ceiling. */
static uint64_t
zfshandle_cmd_right(u_long cmd)
{

	switch (cmd) {
	case ZFD_SET_PROP:
	case ZFD_INHERIT:
	case ZPD_SET_PROP:
		return (ZH_PROPS_WRITE);
	case ZFD_SNAPSHOT:
		return (ZH_SNAPSHOT);
	case ZFD_BOOKMARK:
		return (ZH_BOOKMARK);
	case ZFD_SNAP_DESTROY:
	case ZFD_DESTROY_BOOKMARK:
		return (ZH_SNAP_DESTROY);
	case ZFD_ROLLBACK:
		return (ZH_ROLLBACK);
	case ZFD_CREATE:
	case ZFD_CLONE:
		return (ZH_CREATE);
	case ZFD_DESTROY:
		return (ZH_DESTROY);
	case ZFD_RENAME:
		return (ZH_RENAME);
	case ZFD_PROMOTE:
		return (ZH_PROMOTE);
	case ZFD_SEND:
		return (ZH_SEND);
	case ZFD_RECV:
		return (ZH_RECV);
	case ZFD_HOLD:
		return (ZH_HOLD);
	case ZFD_RELEASE:
		return (ZH_RELEASE);
	case ZFD_BLKOPEN:
	case ZFD_MOUNT:
	case ZFD_UNMOUNT:
		return (ZH_MOUNT);
	case ZPD_SCRUB:
		return (ZH_SCRUB);
	default:
		return (0);
	}
}

static int
zfshandle_op_limit(zfshandle_t *zh, struct zfd_limit_args *args)
{
	zfd_opset_t valid;

	valid = (zh->zh_flags & ZHF_POOL) != 0 ? ZFD_OP_POOL_ALL :
	    ZFD_OP_DATASET_ALL;
	if ((args->zl_ops & ~valid) != 0)
		return (SET_ERROR(EINVAL));
	mutex_enter(&zh->zh_lock);
	if ((args->zl_ops & ~zh->zh_ops) != 0) {
		mutex_exit(&zh->zh_lock);
		return (SET_ERROR(ENOTCAPABLE));
	}
	zh->zh_ops = args->zl_ops;
	mutex_exit(&zh->zh_lock);
	return (0);
}

static int
zfshandle_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
	zfshandle_t *zh = fp->f_data;
	zfd_opset_t op;
	uint64_t right;
	int error;

	sx_xlock(&zfshandle_namespace_sx);
	SDT_PROBE3(trustedzfs, , , op__entry, zh->zh_ds_guid, (int)cmd,
	    zh->zh_rights);

	/*
	 * Pool and dataset handles share the descriptor type but not the
	 * verb set; the generic verbs (INFO/DERIVE and fd plumbing) work
	 * on both.
	 */
	if ((zh->zh_flags & ZHF_POOL) != 0) {
		switch (cmd) {
		case FIONBIO:
		case FIOASYNC:
		case ZFD_INFO:
		case ZFD_DERIVE:
		case ZFD_LIMIT:
		case ZPD_STAT:
		case ZPD_GET_PROPS:
		case ZPD_SET_PROP:
		case ZPD_SCRUB:
		case ZPD_ROOT_OPEN:
			break;
		default:
			error = SET_ERROR(EINVAL);
			goto out;
		}
	} else {
		switch (cmd) {
		case ZPD_STAT:
		case ZPD_GET_PROPS:
		case ZPD_SET_PROP:
		case ZPD_SCRUB:
		case ZPD_ROOT_OPEN:
			error = SET_ERROR(EINVAL);
			goto out;
		default:
			break;
		}
	}
	if (cmd != ZFD_INFO && cmd != FIONBIO && cmd != FIOASYNC &&
	    zfshandle_is_invalid(zh)) {
		error = SET_ERROR(ENXIO);
		goto out;
	}
	right = zfshandle_cmd_right(cmd);
	if (right != 0 && (zh->zh_rights & right) != right) {
		error = zfshandle_require(zh, cmd, right);
		goto out;
	}
	op = zfshandle_cmd_op(cmd);
	if (op != 0 && cmd != ZFD_LIMIT && (zh->zh_ops & op) == 0) {
		error = SET_ERROR(ENOTCAPABLE);
		goto out;
	}

	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		error = 0;
		break;
	case ZFD_INFO:
		error = zfshandle_op_info(zh, data);
		break;
	case ZFD_DERIVE:
		error = zfshandle_op_derive(zh, data, td);
		break;
	case ZFD_LIMIT:
		error = zfshandle_op_limit(zh, data);
		break;
	case ZPD_STAT:
		error = zfshandle_op_pool_stat(zh, data);
		break;
	case ZPD_GET_PROPS:
		error = zfshandle_op_pool_get_props(zh, data);
		break;
	case ZPD_SET_PROP:
		error = zfshandle_require(zh, cmd, ZH_PROPS_WRITE);
		if (error == 0)
			error = zfshandle_op_pool_set_prop(zh, data);
		break;
	case ZPD_SCRUB:
		error = zfshandle_require(zh, cmd, ZH_SCRUB);
		if (error == 0)
			error = zfshandle_op_pool_scrub(zh, data);
		break;
	case ZPD_ROOT_OPEN:
		error = zfshandle_op_pool_root_open(zh, data, td);
		break;
	case ZFD_OPENAT:
		error = zfshandle_op_openat(zh, data, td);
		break;
	case ZFD_STAT:
		error = zfshandle_op_stat(zh, data);
		break;
	case ZFD_GET_PROPS:
		error = zfshandle_op_get_props(zh, data);
		break;
	case ZFD_SET_PROP:
		error = zfshandle_require(zh, cmd, ZH_PROPS_WRITE);
		if (error == 0)
			error = zfshandle_op_set_prop(zh, data);
		break;
	case ZFD_SNAPSHOT:
		error = zfshandle_require(zh, cmd, ZH_SNAPSHOT);
		if (error == 0)
			error = zfshandle_op_snapshot(zh, data, active_cred);
		break;
	case ZFD_SNAP_DESTROY:
		error = zfshandle_require(zh, cmd, ZH_SNAP_DESTROY);
		if (error == 0)
			error = zfshandle_op_snap_destroy(zh, data, active_cred);
		break;
	case ZFD_ROLLBACK:
		error = zfshandle_require(zh, cmd, ZH_ROLLBACK);
		if (error == 0)
			error = zfshandle_op_rollback(zh, data, active_cred);
		break;
	case ZFD_CREATE:
		error = zfshandle_require(zh, cmd, ZH_CREATE);
		if (error == 0)
			error = zfshandle_op_create(zh, data, td);
		break;
	case ZFD_DESTROY:
		error = zfshandle_require(zh, cmd, ZH_DESTROY);
		if (error == 0)
			error = zfshandle_op_destroy(zh, data, active_cred);
		break;
	case ZFD_RENAME:
		error = zfshandle_require(zh, cmd, ZH_RENAME);
		if (error == 0)
			error = zfshandle_op_rename(zh, data);
		break;
	case ZFD_CLONE:
		error = zfshandle_require(zh, cmd, ZH_CREATE);
		if (error == 0)
			error = zfshandle_op_clone(zh, data, td);
		break;
	case ZFD_SEND:
		error = zfshandle_require(zh, cmd, ZH_SEND);
		if (error == 0)
			error = zfshandle_op_send(zh, data, active_cred);
		break;
	case ZFD_RECV:
		error = zfshandle_require(zh, cmd, ZH_RECV);
		if (error == 0)
			error = zfshandle_op_recv(zh, data, active_cred);
		break;
	case ZFD_HOLD:
		error = zfshandle_require(zh, cmd, ZH_HOLD);
		if (error == 0)
			error = zfshandle_op_hold(zh, data, B_TRUE);
		break;
	case ZFD_RELEASE:
		error = zfshandle_require(zh, cmd, ZH_RELEASE);
		if (error == 0)
			error = zfshandle_op_hold(zh, data, B_FALSE);
		break;
	case ZFD_LIST_CHILDREN:
		/* Enumerating descendants needs a subtree grant. */
		if ((zh->zh_flags & ZHF_SUBTREE) == 0)
			error = SET_ERROR(ENOTCAPABLE);
		else
			error = zfshandle_op_list(zh, data, B_FALSE);
		break;
	case ZFD_LIST_SNAPS:
		error = zfshandle_op_list(zh, data, B_TRUE);
		break;
	case ZFD_GET_ONE_PROP:
		error = zfshandle_op_get_one_prop(zh, data);
		break;
	case ZFD_HOLDS:
		error = zfshandle_op_holds(zh, data);
		break;
	case ZFD_INHERIT:
		error = zfshandle_require(zh, cmd, ZH_PROPS_WRITE);
		if (error == 0)
			error = zfshandle_op_inherit(zh, data);
		break;
	case ZFD_PROMOTE:
		error = zfshandle_require(zh, cmd, ZH_PROMOTE);
		if (error == 0)
			error = zfshandle_op_promote(zh);
		break;
	case ZFD_BOOKMARK:
		error = zfshandle_require(zh, cmd, ZH_BOOKMARK);
		if (error == 0)
			error = zfshandle_op_bookmark(zh, data);
		break;
	case ZFD_LIST_BOOKMARKS:
		error = zfshandle_op_list_bookmarks(zh, data);
		break;
	case ZFD_DESTROY_BOOKMARK:
		error = zfshandle_require(zh, cmd, ZH_SNAP_DESTROY);
		if (error == 0)
			error = zfshandle_op_destroy_bookmark(zh, data);
		break;
	case ZFD_BLKOPEN:
		error = zfshandle_require(zh, cmd, ZH_MOUNT);
		if (error == 0)
			error = zfshandle_op_blkopen(zh, data, td);
		break;
	case ZFD_MOUNT:
		error = zfshandle_require(zh, cmd, ZH_MOUNT);
		if (error == 0)
			error = zfshandle_op_mount(zh, data, td);
		break;
	case ZFD_UNMOUNT:
		error = zfshandle_require(zh, cmd, ZH_MOUNT);
		if (error == 0) {
			mutex_enter(&zh->zh_lock);
			error = zh->zh_anon_mounting ? SET_ERROR(EBUSY) :
			    (zh->zh_anon_mp == NULL ? SET_ERROR(ENOENT) : 0);
			mutex_exit(&zh->zh_lock);
			if (error == 0)
				zfshandle_anon_unmount(zh, td);
		}
		break;
	default:
		error = SET_ERROR(ENOTTY);
		break;
	}

out:
	SDT_PROBE3(trustedzfs, , , op__return, zh->zh_ds_guid, (int)cmd,
	    error);
	sx_xunlock(&zfshandle_namespace_sx);
	return (error);
}

static int
zfshandle_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	zfshandle_t *zh = fp->f_data;
	int revents = 0;

	mutex_enter(&zh->zh_lock);
	if (zh->zh_invalid)
		revents = events & (POLLIN | POLLRDNORM);
	else
		selrecord(td, &zh->zh_sel);
	mutex_exit(&zh->zh_lock);
	return (revents);
}

static void
zfshandle_kq_detach(struct knote *kn)
{
	zfshandle_t *zh = kn->kn_hook;

	knlist_remove(&zh->zh_sel.si_note, kn, 0);
}

static int
zfshandle_kq_event(struct knote *kn, long hint)
{
	zfshandle_t *zh = kn->kn_hook;

	/* knlist_init_sx() invokes filters with the handle lock held. */
	kn->kn_data = 0;
	return (zh->zh_invalid ? 1 : 0);
}

static const struct filterops zfshandle_rfiltops = {
	.f_isfd = 1,
	.f_detach = zfshandle_kq_detach,
	.f_event = zfshandle_kq_event,
	.f_copy = knote_triv_copy,
};

static int
zfshandle_kqfilter(struct file *fp, struct knote *kn)
{
	zfshandle_t *zh = fp->f_data;

	if (kn->kn_filter != EVFILT_READ)
		return (EINVAL);
	kn->kn_fop = &zfshandle_rfiltops;
	kn->kn_hook = zh;
	knlist_add(&zh->zh_sel.si_note, kn, 0);
	return (0);
}

static int
zfshandle_stat(struct file *fp, struct stat *sb, struct ucred *active_cred)
{
	bzero(sb, sizeof (*sb));
	sb->st_mode = S_IFIFO;
	return (0);
}

static int
zfshandle_close(struct file *fp, struct thread *td)
{
	zfshandle_t *zh = fp->f_data;

	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	/* The handle anchors any anonymous mount: last close unmounts. */
	zfshandle_anon_unmount(zh, td != NULL ? td : curthread);
	zfshandle_free(zh);
	return (0);
}

static int
zfshandle_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{
	zfshandle_t *zh = fp->f_data;

	kif->kf_type = KF_TYPE_ZFSHANDLE;
	kif->kf_un.kf_zfshandle.kf_zh_ds_guid = zh->zh_ds_guid;
	kif->kf_un.kf_zfshandle.kf_zh_pool_guid = zh->zh_pool_guid;
	kif->kf_un.kf_zfshandle.kf_zh_rights = zh->zh_rights;
	kif->kf_un.kf_zfshandle.kf_zh_flags = zh->zh_flags & ZHF_ALL;
	mutex_enter(&zh->zh_lock);
	kif->kf_un.kf_zfshandle.kf_zh_valid = zh->zh_invalid ? 0 : 1;
	(void) strlcpy(kif->kf_path, zh->zh_name, sizeof (kif->kf_path));
	mutex_exit(&zh->zh_lock);
	return (0);
}
