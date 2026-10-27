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
#include <sys/cmn_err.h>
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
#include <sys/dmu_recv.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dataset.h>
#include <sys/txg.h>
#include <sys/dsl_dir.h>
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
#include <sys/zfs_znode.h>
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
/* Anonymous mount anchored/joined/released: ds guid, anchoring handles, joined. */
SDT_PROBE_DEFINE3(trustedzfs, , , anon__mount,
    "uint64_t", "u_int", "int");
SDT_PROBE_DEFINE2(trustedzfs, , , anon__release,
    "uint64_t", "u_int");
/* The last anchor's unmount failed (errno): the mount stays, re-anchored. */
SDT_PROBE_DEFINE2(trustedzfs, , , anon__unmount__failed,
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

/*
 * Anonymous mounts are shared per dataset.  A dataset is mounted once; every
 * handle that asks to mount it while that mount exists JOINS it (its own root
 * directory descriptor over the same mount) and becomes one more anchor.  The
 * mount goes away when the last anchoring handle closes or unmounts.  This is
 * what lets several consumers -- the units of one bundle over a shared store,
 * or one consumer's several claims -- hold the same store at the same time:
 * the VFS refuses a second mount of an already-mounted objset (EBUSY), so
 * without sharing, only the first claimant could ever reach a shared store.
 */
struct zfshandle_anon {
	LIST_ENTRY(zfshandle_anon) za_link;
	uint64_t	za_pool_guid;
	uint64_t	za_ds_guid;
	struct mount	*za_mp;
	u_int		za_refs;	/* anchoring handles (each holds a vfs_ref) */
	boolean_t	za_rdonly;
	boolean_t	za_mounting;	/* being mounted; joiners wait out (EBUSY) */
};

static LIST_HEAD(, zfshandle_anon) zfshandle_anon_list =
    LIST_HEAD_INITIALIZER(zfshandle_anon_list);
static struct mtx zfshandle_anon_mtx;
MTX_SYSINIT(zfshandle_anon_mtx, &zfshandle_anon_mtx, "zfshandle anon mounts",
    MTX_DEF);

/*
 * The root directory descriptor ZFD_MOUNT hands back anchors the mount as
 * well: it is a plain vnode descriptor except that its close drops the anchor.
 * So a store lives as long as ANY holder keeps a descriptor into it -- the
 * consumer that was delivered the directory, or the provider's handle -- and
 * the provider that mounted it may die and be relaunched without the store
 * being unmounted under its consumers.  Built from the exported vnode fileops
 * on first use (a static initializer cannot copy a const struct).
 */
static struct fileops zfshandle_anon_dir_ops;
static boolean_t zfshandle_anon_dir_ops_ready;
static void zfshandle_anon_release(struct mount *mp, struct thread *td);

static int
zfshandle_anon_dir_close(struct file *fp, struct thread *td)
{
	/*
	 * The anchored mount is recorded in f_data at creation: v_mount goes
	 * NULL once any unmount (a forced one, shutdown's unmount-all) reclaims
	 * the vnode, and the anchor's reference must be dropped regardless --
	 * a reference that is never dropped leaves vfs_mount_destroy sleeping
	 * forever.
	 */
	struct mount *mp = fp->f_data;
	int error;

	error = vnops.fo_close(fp, td);
	if (mp != NULL)
		zfshandle_anon_release(mp, td != NULL ? td : curthread);
	return (error);
}

static const struct fileops *
zfshandle_anon_dir_fileops(void)
{
	mtx_lock(&zfshandle_anon_mtx);
	if (!zfshandle_anon_dir_ops_ready) {
		zfshandle_anon_dir_ops = vnops;
		zfshandle_anon_dir_ops.fo_close = zfshandle_anon_dir_close;
		zfshandle_anon_dir_ops_ready = B_TRUE;
	}
	mtx_unlock(&zfshandle_anon_mtx);
	return (&zfshandle_anon_dir_ops);
}

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
		    const char *, uint64_t, uint32_t, u_long, int32_t *);
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
	    args->zr_flags, ZPD_ROOT_OPEN, &args->zr_fd));
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
	zfs_prop_t prop;
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

	/* The ioctl pipeline assumes native read-only properties were rejected
	 * by its userspace frontend. This typed kernel API must do that too. */
	prop = zfs_name_to_prop(args->zsp_name);
	if (prop != ZPROP_USERPROP && zfs_prop_readonly(prop))
		return (SET_ERROR(EINVAL));


	nvl = fnvlist_alloc();
	if (args->zsp_is_string)
		fnvlist_add_string(nvl, args->zsp_name, args->zsp_strval);
	else
		fnvlist_add_uint64(nvl, args->zsp_name, args->zsp_intval);
	/* Use the normal property pipeline: validation and special setters are
	 * required for quotas, reservations and filesystem/snapshot counters.
	 * Writing the property ZAP directly can report success without enabling
	 * the corresponding enforcement state. ZH_PROPS_WRITE was checked by
	 * dispatch; the scoped credential preserves configured limit checks. */
	error = zfshandle_ioc(ZFS_IOC_SET_PROP, name, NULL, 0, nvl, NULL);
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

static cred_t *zfshandle_cred_enter_from(cred_t *);
static void zfshandle_cred_exit(cred_t *);

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
	/* Retain the caller's identity, but do not let UID/property privileges
	 * waive snapshot limits for this capability-authorized operation. The
	 * DSL snapshots the scoped credential for its transaction checks. */
	cred_t *saved = zfshandle_cred_enter_from(CRED());
	error = dsl_dataset_snapshot(snaps, NULL, NULL);
	zfshandle_cred_exit(saved);
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

#ifdef MAC
/* Pin the implicit "latest" choice to one actual snapshot before admission.
 * Passing its name to dsl_dataset_rollback also retains the DSL transaction's
 * check that this exact snapshot remains the most recent rollback target. */
static int
zfshandle_latest_snapshot(zfshandle_t *zh, char *name)
{
	dsl_pool_t *dp;
	dsl_dataset_t *ds, *snapshot;
	int error;

	sx_assert(&zfshandle_namespace_sx, SA_XLOCKED);
	error = zfshandle_hold(zh, FTAG, &dp, &ds);
	if (error != 0)
		return (error);
	if (ds->ds_is_snapshot)
		error = SET_ERROR(EINVAL);
	else if (dsl_dataset_phys(ds)->ds_prev_snap_txg < TXG_INITIAL)
		error = SET_ERROR(ESRCH);
	else {
		error = dsl_dataset_hold_obj(dp,
		    dsl_dataset_phys(ds)->ds_prev_snap_obj, FTAG, &snapshot);
		if (error == 0) {
			dsl_dataset_name(snapshot, name);
			dsl_dataset_rele(snapshot, FTAG);
		}
	}
	zfshandle_rele(dp, ds, FTAG);
	return (error);
}
#endif

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
	if (tgt == NULL) {
		error = zfshandle_latest_snapshot(zh, target);
		if (error != 0)
			return (error);
		tgt = target;
	}
	error = mac_mount_check_snapshot_revert(cred, tgt);
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
/* A private credential carries the limit policy into deferred DSL checks.
 * Never mark the shared kernel or process credential. The marker only removes
 * administrative limit exemptions; it grants no operation or property right. */
static cred_t *
zfshandle_cred_enter_from(cred_t *base)
{
	struct thread *td = curthread;
	cred_t *saved = td->td_ucred;
	cred_t *scoped = crdup(base);

	scoped->cr_flags |= CRED_FLAG_CAPABILITY_LIMITS;
	td->td_ucred = scoped;
	return (saved);
}

static cred_t *
zfshandle_cred_enter(void)
{

	return (zfshandle_cred_enter_from(kcred));
}

static void
zfshandle_cred_exit(cred_t *saved)
{
	struct thread *td = curthread;
	cred_t *scoped = td->td_ucred;

	td->td_ucred = saved;
	crfree(scoped);
}

static int
zfshandle_ioc_context(uint64_t ioc, const char *name, const char *value,
    uint64_t cookie, uint64_t zflags, nvlist_t *innvl, nvlist_t **outnvlp,
    const dmu_recv_io_t *io)
{
	const size_t dstlen = 128 * 1024;
	zfs_cmd_t *zc;
	char *packed = NULL, *dst;
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
	/*
	 * Always supply an output buffer, even when the caller discards the
	 * result.  zfsdev_ioctl_common() reports an nvlist_smush() or
	 * put_nvlist() failure as the ioctl's errno when the operation itself
	 * succeeded, so a zero-sized destination turns a successful vector
	 * that returns output (ZFS_IOC_RECV_NEW: read_bytes, error_flags,
	 * errors) into ENOMEM after it has already committed.
	 */
	dst = vmem_alloc(dstlen, KM_SLEEP);
	zc->zc_nvlist_dst = (uintptr_t)dst;
	zc->zc_nvlist_dst_size = dstlen;

	saved = zfshandle_cred_enter();
	if (io != NULL) {
		ASSERT3U(ioc, ==, ZFS_IOC_RECV_NEW);
		error = zfsdev_ioctl_recv_io(zc, io);
	} else {
		error = zfsdev_ioctl_common(ioc - ZFS_IOC_FIRST, zc, FKIOCTL);
	}
	zfshandle_cred_exit(saved);

	if (error == 0 && outnvlp != NULL && zc->zc_nvlist_dst_filled)
		*outnvlp = fnvlist_unpack(dst, zc->zc_nvlist_dst_size);

	if (packed != NULL)
		fnvlist_pack_free(packed, plen);
	vmem_free(dst, dstlen);
	vmem_free(zc, sizeof (*zc));
	return (error);
}

static int
zfshandle_ioc_flags(uint64_t ioc, const char *name, const char *value,
    uint64_t cookie, uint64_t zflags, nvlist_t *innvl, nvlist_t **outnvlp)
{
	return (zfshandle_ioc_context(ioc, name, value, cookie, zflags,
	    innvl, outnvlp, NULL));
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
    uint64_t rights, uint32_t flags, u_long command, int32_t *fdp)
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

/* Creation has succeeded, but descriptor publication can still fail.
 * Preserve that failure for callers; report an unsuccessful rollback instead
 * of silently leaving a newly created dataset behind. The namespace gate
 * remains held across publication and rollback, as for the original mutation. */
static int
zfshandle_publish_child(struct thread *td, zfshandle_t *zh, const char *full,
    uint64_t rights, uint32_t flags, u_long command, int32_t *fdp)
{
	int error, cleanup_error;

	error = zfshandle_mint_child(td, zh, full, rights, flags, command, fdp);
	if (error == 0)
		return (0);
	cleanup_error = zfshandle_ioc(ZFS_IOC_DESTROY, full, NULL, 0, NULL, NULL);
	if (cleanup_error != 0)
		cmn_err(CE_WARN, "TrustedZFS: child %s publication failed (%d); "
		    "cleanup failed (%d), dataset may remain", full, error,
		    cleanup_error);
	return (error);
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

	return (zfshandle_publish_child(td, zh, full, zh->zh_rights,
	    args->zc_handle_flags, ZFD_CREATE, &args->zc_fd));
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
zfshandle_op_rename(zfshandle_t *zh, struct zfd_rename_args *args,
    struct ucred *cred)
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
	/* Rename changes both parent namespaces. Authority over the dataset
	 * itself does not authorize modifying its containing namespace, even
	 * for a one-component destination. Both endpoints must be descendants
	 * of this same granted subtree. */
	if ((zh->zh_flags & ZHF_SUBTREE) == 0 || args->zr_from[0] == '\0')
		return (SET_ERROR(ENOTCAPABLE));
	error = zfshandle_relname(zh, args->zr_from, B_FALSE, from,
	    sizeof (from));
	if (error != 0)
		return (error);
	error = zfshandle_relname(zh, args->zr_to, B_FALSE, to,
	    sizeof (to));
	if (error != 0)
		return (error);
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

	return (zfshandle_publish_child(td, zh, full, zh->zh_rights,
	    0, ZFD_CLONE, &args->zc_fd));
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

/* Pin the admitted snapshots before dropping namespace serialization. The
 * numeric-object send path cannot substitute an object after a rename, and
 * long holds prevent destruction/reuse until streaming has finished. */
static int
zfshandle_send_pinned(zfshandle_t *zh, const char *full, const char *from,
    struct zfd_send_args *args)
{
	dsl_pool_t *dp;
	dsl_dataset_t *snapshot, *base = NULL;
	zfs_cmd_t *zc;
	cred_t *saved;
	int error;

	sx_assert(&zfshandle_namespace_sx, SA_XLOCKED);
	zc = vmem_zalloc(sizeof(*zc), KM_SLEEP);
	error = dsl_pool_hold(full, zc, &dp);
	if (error != 0)
		goto out;
	if (spa_guid(dp->dp_spa) != zh->zh_pool_guid) {
		error = SET_ERROR(ENXIO);
		goto drop_pool;
	}
	error = dsl_dataset_hold(dp, full, zc, &snapshot);
	if (error != 0)
		goto drop_pool;
	if (!dsl_dataset_is_snapshot(snapshot)) {
		error = SET_ERROR(EINVAL);
		goto drop_snapshot;
	}
	if (from[0] != '\0') {
		error = dsl_dataset_hold(dp, from, zc, &base);
		if (error != 0)
			goto drop_snapshot;
		if (!dsl_dataset_is_snapshot(base)) {
			error = SET_ERROR(EINVAL);
			goto drop_base;
		}
	}
	(void)strlcpy(zc->zc_name, full, sizeof(zc->zc_name));
	zc->zc_sendobj = snapshot->ds_object;
	zc->zc_fromobj = base != NULL ? base->ds_object : 0;
	zc->zc_cookie = args->zs_out_fd;
	/* These four flags share the legacy SEND ioctl ABI, which drives
	 * dmu_send_obj and the normal output descriptor/feature checks. */
	CTASSERT(ZFD_SEND_EMBED == 0x1 && ZFD_SEND_LARGEBLOCK == 0x2 &&
	    ZFD_SEND_COMPRESS == 0x4 && ZFD_SEND_RAW == 0x8);
	zc->zc_flags = args->zs_flags;
	dsl_dataset_long_hold(snapshot, zc);
	if (base != NULL)
		dsl_dataset_long_hold(base, zc);
	dsl_pool_rele(dp, zc);
	/* Never hold the namespace gate while waiting for output consumers.
	 * Dataset references, not names, now carry the admitted identity. */
	sx_xunlock(&zfshandle_namespace_sx);
	saved = zfshandle_cred_enter();
	error = zfsdev_ioctl_common(ZFS_IOC_SEND - ZFS_IOC_FIRST, zc, FKIOCTL);
	zfshandle_cred_exit(saved);
	if (base != NULL) {
		dsl_dataset_long_rele(base, zc);
		dsl_dataset_rele(base, zc);
	}
	dsl_dataset_long_rele(snapshot, zc);
	dsl_dataset_rele(snapshot, zc);
	sx_xlock(&zfshandle_namespace_sx);
	goto out;
drop_base:
	if (base != NULL)
		dsl_dataset_rele(base, zc);
drop_snapshot:
	dsl_dataset_rele(snapshot, zc);
drop_pool:
	dsl_pool_rele(dp, zc);
out:
	vmem_free(zc, sizeof(*zc));
	return (error);
}

static int
zfshandle_op_send(zfshandle_t *zh, struct zfd_send_args *args,
    struct ucred *cred)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char from[ZFS_MAX_DATASET_NAME_LEN] = {0};
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

	if (args->zs_fromsnap[0] != '\0') {
		char *at = strchr(full, '@');

		if (zfs_component_namecheck(args->zs_fromsnap, NULL,
		    NULL) != 0 || at == NULL ||
		    snprintf(from, sizeof (from), "%.*s@%s",
		    (int)(at - full), full, args->zs_fromsnap) >=
		    (int)sizeof (from)) {
			return (SET_ERROR(EINVAL));
		}
	}
	error = zfshandle_send_begin(zh);
	if (error != 0)
		return (error);
	error = zfshandle_send_pinned(zh, full, from, args);
	zfshandle_send_finish(zh, error);
	return (error);
}

struct zfshandle_recv_id {
	uint64_t object, guid;
};
struct zfshandle_recv_context {
	zfshandle_t *root;
	char rootname[ZFS_MAX_DATASET_NAME_LEN];
	char parent[ZFS_MAX_DATASET_NAME_LEN];
	char target[ZFS_MAX_DATASET_NAME_LEN];
	struct zfshandle_recv_id parent_id, target_id;
	boolean_t target_exists;
};

static int
zfshandle_recv_identity(uint64_t pool, const char *name,
    struct zfshandle_recv_id *identity)
{
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	int error;

	sx_assert(&zfshandle_namespace_sx, SA_XLOCKED);
	error = dsl_pool_hold(name, FTAG, &dp);
	if (error != 0)
		return (error);
	if (spa_guid(dp->dp_spa) != pool) {
		dsl_pool_rele(dp, FTAG);
		return (SET_ERROR(ENXIO));
	}
	error = dsl_dataset_hold(dp, name, FTAG, &ds);
	if (error == 0) {
		identity->object = ds->ds_object;
		identity->guid = dsl_dataset_phys(ds)->ds_guid;
		dsl_dataset_rele(ds, FTAG);
	}
	dsl_pool_rele(dp, FTAG);
	return (error);
}

static boolean_t
zfshandle_recv_same(const struct zfshandle_recv_id *a,
    const struct zfshandle_recv_id *b)
{
	return (a->object == b->object && a->guid == b->guid);
}

static int
zfshandle_recv_validate(struct zfshandle_recv_context *ctx,
    const dmu_recv_cookie_t *drc)
{
	struct zfshandle_recv_id actual, expected = ctx->target_id;
	char rootname[ZFS_MAX_DATASET_NAME_LEN];
	boolean_t exists = ctx->target_exists;
	int error;

	/* Root/parent replacement is distinct from target replacement. Capture
	 * and compare actual objects; a matching pathname alone is not enough. */
	if (zfshandle_resolve_name(ctx->root, rootname, sizeof(rootname)) != 0 ||
	    strcmp(rootname, ctx->rootname) != 0 ||
	    zfshandle_recv_identity(ctx->root->zh_pool_guid, ctx->parent,
	    &actual) != 0 || !zfshandle_recv_same(&actual, &ctx->parent_id))
		return (SET_ERROR(ESTALE));
	/* BEGIN may read payload before creating anything. Once a new receive
	 * owns its dataset, that owned object becomes the only acceptable target. */
	if (!exists && drc->drc_newfs && drc->drc_ds != NULL) {
		expected.object = drc->drc_ds->ds_object;
		expected.guid = dsl_dataset_phys(drc->drc_ds)->ds_guid;
		exists = B_TRUE;
	}
	error = zfshandle_recv_identity(ctx->root->zh_pool_guid, ctx->target,
	    &actual);
	if (!exists)
		return (error == ENOENT ? 0 : SET_ERROR(ESTALE));
	return (error == 0 && zfshandle_recv_same(&actual, &expected) ?
	    0 : SET_ERROR(ESTALE));
}

static int
zfshandle_recv_read(dmu_recv_cookie_t *drc, void *buffer, size_t length,
    ssize_t *resid, void *argument)
{
	struct zfshandle_recv_context *ctx = argument;
	int error, scope_error;

	sx_assert(&zfshandle_namespace_sx, SA_XLOCKED);
	sx_xunlock(&zfshandle_namespace_sx);
	error = zfs_file_read(drc->drc_fp, buffer, length, resid);
	sx_xlock(&zfshandle_namespace_sx);
	scope_error = zfshandle_recv_validate(ctx, drc);
	/* Restore serialization even on EOF, interruption or replacement. The
	 * normal receive failure path cleans its owned staging object while
	 * name-based commit/property handling cannot run on a replacement. */
	return (scope_error != 0 ? scope_error : error);
}

static int
zfshandle_op_recv(zfshandle_t *zh, struct zfd_recv_args *args,
    struct ucred *cred)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char fsname[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl;
	struct zfshandle_recv_context context = {.root = zh};
	dmu_recv_io_t io = {.read = zfshandle_recv_read, .argument = &context};
	char *slash;
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

	/* All bindings are obtained under the admission gate, before any read
	 * can release it. Typed receive supplies no name-based property lists. */
	error = zfshandle_resolve_name(zh, context.rootname, sizeof(context.rootname));
	if (error != 0)
		return (error);
	(void)strlcpy(context.target, fsname, sizeof(context.target));
	(void)strlcpy(context.parent, fsname, sizeof(context.parent));
	slash = strrchr(context.parent, '/');
	if (slash == NULL)
		return (SET_ERROR(EINVAL));
	*slash = '\0';
	error = zfshandle_recv_identity(zh->zh_pool_guid, context.parent, &context.parent_id);
	if (error != 0)
		return (error);
	error = zfshandle_recv_identity(zh->zh_pool_guid, fsname, &context.target_id);
	if (error != 0 && error != ENOENT)
		return (error);
	context.target_exists = error == 0;

	innvl = fnvlist_alloc();
	fnvlist_add_string(innvl, "snapname", full);
	fnvlist_add_byte_array(innvl, "begin_record",
	    args->zr_begin_record, ZFD_BEGIN_RECORD_SIZE);
	fnvlist_add_int32(innvl, "input_fd", args->zr_input_fd);
	if (args->zr_force)
		fnvlist_add_boolean(innvl, "force");

	error = zfshandle_ioc_context(ZFS_IOC_RECV_NEW, fsname, NULL, 0, 0,
	    innvl, NULL, &io);
	nvlist_free(innvl);
	return (error);
}

static int
zfshandle_op_hold(zfshandle_t *zh, struct zfd_hold_args *args,
    boolean_t hold)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char pool[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl, *holds, *errors = NULL;
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
		    &errors);
	} else {
		nvlist_t *tags = fnvlist_alloc();

		fnvlist_add_boolean(tags, args->zh_tag);
		innvl = fnvlist_alloc();
		fnvlist_add_nvlist(innvl, full, tags);
		nvlist_free(tags);
		error = zfshandle_ioc(ZFS_IOC_RELEASE, pool, NULL, 0, innvl,
		    &errors);
	}
	nvlist_free(innvl);
	/* The bulk ioctl reports absent snapshots/tags in its output list
	 * without failing the whole batch. This handle operation requests
	 * exactly one snapshot/tag, so any object error is its result. */
	if (error == 0 && errors != NULL && !nvlist_empty(errors)) {
		nvpair_t *pair = nvlist_next_nvpair(errors, NULL);
		int32_t object_error;

		if (nvlist_next_nvpair(errors, pair) != NULL ||
		    nvpair_value_int32(pair, &object_error) != 0 ||
		    object_error <= 0)
			error = SET_ERROR(EIO);
		else
			error = object_error;
	}
	if (errors != NULL)
		nvlist_free(errors);
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

	/* Computed accounting properties are not stored property-ZAP values.
	 * Ask the normal dataset/directory statistics producers first. */
	if (zfs_prop_get_type(prop) != PROP_TYPE_STRING) {
		dsl_pool_t *dp;
		dsl_dataset_t *ds;
		nvlist_t *stats, *value;

		error = zfshandle_hold(zh, FTAG, &dp, &ds);
		if (error != 0)
			return (error);
		stats = fnvlist_alloc();
		dsl_dir_stats(ds->ds_dir, stats);
		dsl_dataset_stats(ds, stats);
		zfshandle_rele(dp, ds, FTAG);
		error = nvlist_lookup_nvlist(stats, args->zgo_name, &value);
		if (error == 0)
			error = nvlist_lookup_uint64(value, ZPROP_VALUE,
			    &args->zgo_intval);
		nvlist_free(stats);
		if (error == 0) {
			args->zgo_is_string = 0;
			args->zgo_source = ZPROP_SRC_NONE;
			return (0);
		}
	}

	/* Native property: read the held identity, never re-resolve its name.
	 * Capture the name and setpoint under the same pool configuration hold. */
	{
		dsl_pool_t *dp;
		dsl_dataset_t *ds;

		error = zfshandle_hold(zh, FTAG, &dp, &ds);
		if (error != 0)
			return (error);
		dsl_dataset_name(ds, name);
		setpoint[0] = '\0';
		if (zfs_prop_get_type(prop) == PROP_TYPE_STRING) {
			error = dsl_prop_get_ds(ds, args->zgo_name, 1,
			    sizeof (args->zgo_strval), args->zgo_strval, setpoint);
			args->zgo_is_string = 1;
		} else {
			error = dsl_prop_get_ds(ds, args->zgo_name,
			    sizeof (args->zgo_intval), 1, &args->zgo_intval,
			    setpoint);
			args->zgo_is_string = 0;
		}
		zfshandle_rele(dp, ds, FTAG);
		if (error != 0)
			return (error);
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
	cred_t *saved_cred;
	int error, niov;
	static const char fstype[] = "zfs";
	static const char ro[] = "ro";

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
	ZH_OPT("fspath", VFS_ANON_FSPATH);
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
	 * the kernel cred across the mount so the ambient secpolicy_fs_mount()
	 * re-check (which reads curthread's cred) does not reject an
	 * unprivileged capability holder; the mount is thus root-owned exactly
	 * as a switchboard-initiated mount was.  The dir fd opened below still
	 * uses the caller's restored cred.
	 */
	saved_cred = zfshandle_cred_enter();
	error = vfs_mount_anon(td, fstype, opts, rdonly ? MNT_RDONLY : 0,
	    saved_cred, mpp);
	zfshandle_cred_exit(saved_cred);
	return (error);
}

/* zfshandle_anon_mtx must be held. */
static struct zfshandle_anon *
zfshandle_anon_find(uint64_t pool_guid, uint64_t ds_guid)
{
	struct zfshandle_anon *za;

	mtx_assert(&zfshandle_anon_mtx, MA_OWNED);
	LIST_FOREACH(za, &zfshandle_anon_list, za_link)
		if (za->za_pool_guid == pool_guid && za->za_ds_guid == ds_guid)
			return (za);
	return (NULL);
}

/*
 * Drop one anchoring handle's reference on a shared anonymous mount.  Every
 * anchor holds a vfs_ref; a non-last anchor simply releases its reference.
 * The last anchor unmounts: dounmount() consumes one reference (the
 * kern_unmount contract) -- on success AND on every error path.  Shutdown's
 * unmount-all can beat us to it, so re-verify list membership by identity
 * under mountlist_mtx first.
 *
 * Invariant: an entry's za_mp is only ever dereferenced while za_refs > 0,
 * and every one of those za_refs is backed by a vfs_ref some anchor holds.
 * That reference is what keeps vfs_mount_destroy() from completing under
 * the registry.  The registry itself never holds a reference (it would hang
 * shutdown's unmount-all in vfs_mount_destroy).
 */
static void
zfshandle_anon_release(struct mount *mp, struct thread *td)
{
	struct zfshandle_anon *za;
	struct mount *iter;
	boolean_t onlist;
	uint64_t guid __unused = 0;
	u_int left __unused = 0;

	mtx_lock(&zfshandle_anon_mtx);
	LIST_FOREACH(za, &zfshandle_anon_list, za_link)
		if (za->za_mp == mp)
			break;
	if (za != NULL) {
		guid = za->za_ds_guid;
		KASSERT(za->za_refs > 0, ("anon mount with no anchors"));
		left = --za->za_refs;
		if (left == 0) {
			/*
			 * Last anchor: keep the entry listed but busy while the
			 * unmount runs, so a claim racing the teardown is
			 * refused (EBUSY, and retried by the caller) instead of
			 * attempting a second VFS mount of an objset still
			 * being torn down.
			 */
			za->za_mounting = B_TRUE;
		} else
			za = NULL;	/* still anchored by others */
	}
	mtx_unlock(&zfshandle_anon_mtx);
	SDT_PROBE2(trustedzfs, , , anon__release, guid, left);
	if (za == NULL) {
		vfs_rel(mp);
		return;
	}

	onlist = B_FALSE;
	mtx_lock(&mountlist_mtx);
	TAILQ_FOREACH(iter, &mountlist, mnt_list) {
		if (iter == mp) {
			onlist = B_TRUE;
			break;
		}
	}
	mtx_unlock(&mountlist_mtx);

	if (onlist) {
		cred_t *saved;
		int error;

		/*
		 * The mount was made under the kernel credential (the
		 * capability, not the caller's uid, is the authority) and must
		 * be unmounted the same way: the last anchor may be closed by
		 * an unprivileged consumer, which secpolicy_fs_unmount would
		 * refuse, leaking the mount with no registry entry.
		 */
		saved = zfshandle_cred_enter();
		error = vfs_unmount_anon(mp, td);
		zfshandle_cred_exit(saved);
		if (error != 0) {
			/*
			 * dounmount() released our reference even though it
			 * failed (every error return does vfs_rel/MNT_REL), so
			 * nothing anchors the mount any more: if the failure
			 * was EBUSY from a concurrent unmount, that unmount
			 * destroys mp as soon as it drains.  The entry cannot
			 * keep pointing at it.  Forget it; a mount that did
			 * survive (VFS_UNMOUNT refused) stays on mountlist as
			 * an orphan that the next claim of the dataset re-finds
			 * by fsid and adopts (zfshandle_anon_adopt), taking a
			 * fresh reference under mountlist_mtx.
			 */
			SDT_PROBE2(trustedzfs, , , anon__unmount__failed, guid,
			    error);
		}
	} else
		vfs_rel(mp);
	mtx_lock(&zfshandle_anon_mtx);
	LIST_REMOVE(za, za_link);
	mtx_unlock(&zfshandle_anon_mtx);
	kmem_free(za, sizeof (*za));
}

/*
 * Find a live anonymous ZFS mount of the dataset whose fsid is derived from
 * fsid_guid that no registry entry tracks -- one left behind by a failed
 * last-anchor unmount -- and take a reference on it.  The lookup is by fsid,
 * never by a remembered pointer, under mountlist_mtx: a mount still on
 * mountlist has not reached vfs_mount_destroy, so the vfs_ref is safe (the
 * vfs_getvfs pattern), and a mount being unmounted is not adopted.  The
 * caller holds the dataset's registry entry in the mounting state, so no
 * other claim can adopt or mount it concurrently.
 */
static int zfshandle_anon_root(zfshandle_t *, struct mount *, struct vnode **);

static int
zfshandle_anon_adopt(zfshandle_t *zh, uint64_t fsid_guid, boolean_t rdonly,
    struct mount **mpp)
{
	struct mount *mp;
	fsid_t fsid;
	int error;

	error = SET_ERROR(ENOENT);
	mtx_lock(&mountlist_mtx);
	TAILQ_FOREACH(mp, &mountlist, mnt_list) {
		fsid = mp->mnt_stat.f_fsid;
		if ((uint32_t)fsid.val[0] != (uint32_t)fsid_guid ||
		    ((uint32_t)fsid.val[1] >> 8) != (uint32_t)(fsid_guid >> 32))
			continue;
		if (strcmp(mp->mnt_stat.f_fstypename, "zfs") != 0 ||
		    (mp->mnt_kern_flag & MNTK_ANON) == 0 ||
		    mp->mnt_vnodecovered != NULL ||
		    strcmp(mp->mnt_stat.f_mntonname, VFS_ANON_FSPATH) != 0)
			continue;
		MNT_ILOCK(mp);
		if ((mp->mnt_kern_flag &
		    (MNTK_UNMOUNT | MNTK_REFEXPIRE)) != 0) {
			error = SET_ERROR(EBUSY);
		} else if (((mp->mnt_flag & MNT_RDONLY) != 0) != rdonly) {
			error = SET_ERROR(rdonly ? EEXIST : EROFS);
		} else {
			MNT_REF(mp);
			*mpp = mp;
			error = 0;
		}
		MNT_IUNLOCK(mp);
		break;
	}
	mtx_unlock(&mountlist_mtx);
	if (error == 0) {
		/* A colliding fsid must not let this handle acquire or tear down
		 * somebody else's mount. Validate before registry ownership. */
		error = zfshandle_anon_root(zh, *mpp, NULL);
		if (error != 0) {
			vfs_rel(*mpp);
			*mpp = NULL;
		}
	}
	return (error);
}

/* Detach the handle from its anonymous mount, if any, and release it. */
static void
zfshandle_anon_unmount(zfshandle_t *zh, struct thread *td)
{
	struct mount *mp;

	mutex_enter(&zh->zh_lock);
	mp = zh->zh_anon_mp;
	zh->zh_anon_mp = NULL;
	mutex_exit(&zh->zh_lock);
	if (mp == NULL)
		return;
	zfshandle_anon_release(mp, td);
}

/*
 * The fsid used by orphan lookup is only a candidate locator: it loses bits
 * and does not identify the pool.  Before publishing any root, check the full
 * pinned handle identity against the mounted objset.  Do this for fresh and
 * cached mounts too, so no attachment path can skip the identity invariant.
 *
 * Our anchor holds a mount reference; busying additionally excludes teardown
 * of mnt_data.  Do not wait for an unmount while holding the namespace gate.
 * The ZFS teardown reader protects z_os during identity inspection.  Never
 * acquire these locks under mountlist_mtx or zfshandle_anon_mtx.
 */
static int
zfshandle_anon_root(zfshandle_t *zh, struct mount *mp, struct vnode **vpp)
{
	zfsvfs_t *zfsvfs;
	objset_t *os;
	int error;

	error = vfs_busy(mp, MBF_NOWAIT);
	if (error != 0)
		return (error);
	zfsvfs = mp->mnt_data;
	if (zfsvfs == NULL) {
		error = SET_ERROR(ESTALE);
		goto out;
	}
	error = zfs_enter(zfsvfs, FTAG);
	if (error != 0)
		goto out;
	os = zfsvfs->z_os;
	if (os == NULL ||
	    spa_guid(dmu_objset_spa(os)) != zh->zh_pool_guid ||
	    dmu_objset_id(os) != zh->zh_dsobj ||
	    dsl_dataset_phys(dmu_objset_ds(os))->ds_guid != zh->zh_ds_guid)
		error = SET_ERROR(ESTALE);
	zfs_exit(zfsvfs, FTAG);
	if (error == 0 && vpp != NULL)
		error = VFS_ROOT(mp, LK_EXCLUSIVE, vpp);
out:
	vfs_unbusy(mp);
	return (error);
}

static int
zfshandle_op_mount(zfshandle_t *zh, struct zfd_mount_args *args,
    struct thread *td)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	struct zfshandle_anon *za, *fresh;
	struct mount *mp;
	struct vnode *vp;
	struct file *fp;
	dsl_pool_t *dp;
	dsl_dataset_t *ds;
	objset_t *os;
	boolean_t rdonly;
	boolean_t joined __unused;
	u_int refs __unused;
	uint64_t fsid_guid;
	int error, fd, flags;

	if (args->zm_rdonly > 1)
		return (SET_ERROR(EINVAL));
	rdonly = args->zm_rdonly ? B_TRUE : B_FALSE;

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
	fsid_guid = 0;
	error = dmu_objset_from_ds(ds, &os);
	if (error == 0 && dmu_objset_type(os) != DMU_OST_ZFS)
		error = SET_ERROR(EINVAL);
	if (error == 0)
		fsid_guid = dmu_objset_fsid_guid(os);
	dsl_dataset_name(ds, name);
	zfshandle_rele(dp, ds, FTAG);
	if (error != 0)
		goto failed;

	/*
	 * Join the dataset's existing anonymous mount, or become the one that
	 * mounts it.  Every ZFD_MOUNT runs under the exclusive namespace lock,
	 * so no joiner can observe the mounting window here; the busy mark
	 * matters for the TEARDOWN window, where the last anchor's release
	 * runs from close(2) without that lock.  A joiner takes its own vfs_ref
	 * exactly as the mounter does.  A read-only join of a read-write mount
	 * (or the reverse) is refused: the mount's writability is shared state,
	 * not this handle's to change.
	 */
	fresh = kmem_zalloc(sizeof (*fresh), KM_SLEEP);
	joined = B_FALSE;
	refs = 1;
	mtx_lock(&zfshandle_anon_mtx);
	za = zfshandle_anon_find(zh->zh_pool_guid, zh->zh_ds_guid);
	if (za != NULL) {
		if (za->za_mounting) {
			error = SET_ERROR(EBUSY);	/* transient: retried */
		} else if (za->za_rdonly != rdonly) {
			/* permanent: the mount's writability is shared state */
			error = SET_ERROR(za->za_rdonly ? EROFS : EEXIST);
		} else {
			/*
			 * A mount an external forced unmount is tearing down
			 * is not joinable: its vnodes are being reclaimed and
			 * its private data freed.
			 */
			MNT_ILOCK(za->za_mp);
			if ((za->za_mp->mnt_kern_flag &
			    (MNTK_UNMOUNT | MNTK_REFEXPIRE)) != 0)
				error = SET_ERROR(EBUSY);
			MNT_IUNLOCK(za->za_mp);
		}
		if (error != 0) {
			mtx_unlock(&zfshandle_anon_mtx);
			kmem_free(fresh, sizeof (*fresh));
			goto failed;
		}
		mp = za->za_mp;
		refs = ++za->za_refs;
		vfs_ref(mp);
		joined = B_TRUE;
		mtx_unlock(&zfshandle_anon_mtx);
		kmem_free(fresh, sizeof (*fresh));
	} else {
		za = fresh;
		za->za_pool_guid = zh->zh_pool_guid;
		za->za_ds_guid = zh->zh_ds_guid;
		za->za_rdonly = rdonly;
		za->za_mounting = B_TRUE;
		LIST_INSERT_HEAD(&zfshandle_anon_list, za, za_link);
		mtx_unlock(&zfshandle_anon_mtx);
		/* Recover an existing mount before attempting creation. Never
		 * reinterpret a creation-policy denial as permission to adopt.
		 * Both adopted and newly created roots still pass vn_open_vnode
		 * below with the caller's current credentials. */
		error = zfshandle_anon_adopt(zh, fsid_guid, rdonly, &mp);
		if (error == ENOENT)
			error = zfshandle_anon_mount(td, name, rdonly, &mp);
		if (error != 0) {
			mtx_lock(&zfshandle_anon_mtx);
			LIST_REMOVE(za, za_link);
			mtx_unlock(&zfshandle_anon_mtx);
			kmem_free(za, sizeof (*za));
			goto failed;
		}
		/*
		 * This handle anchors the mount with the reference
		 * zfshandle_anon_mount (or zfshandle_anon_adopt) handed back
		 * (the kern_unmount-style ref).
		 */
		mtx_lock(&zfshandle_anon_mtx);
		za->za_mp = mp;
		za->za_refs = 1;
		za->za_mounting = B_FALSE;
		mtx_unlock(&zfshandle_anon_mtx);
	}
	SDT_PROBE3(trustedzfs, , , anon__mount, zh->zh_ds_guid, refs,
	    joined ? 1 : 0);

	error = zfshandle_anon_root(zh, mp, &vp);
	if (error != 0)
		goto release;

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		vput(vp);
		goto release;
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
		goto release;
	}
	/*
	 * finit_open() equivalent: bind the vnode and the vnode ops, with the
	 * close hook that makes this descriptor an anchor of the mount.
	 */
	fp->f_vnode = vp;
	if (fp->f_ops == &badfileops)
		finit_vnode(fp, flags, mp, zfshandle_anon_dir_fileops());
	else
		fp->f_data = mp;
	fp->f_flag = flags & FMASK;
	VOP_UNLOCK(vp);

	/*
	 * The descriptor's anchor: taken before the fd becomes visible, so a
	 * close racing finstall releases an anchor that exists.  If finstall
	 * fails, the fdrop below is the last reference and runs the close hook,
	 * which releases this anchor; the handle's own anchor is released by
	 * the error path.
	 */
	vfs_ref(mp);
	mtx_lock(&zfshandle_anon_mtx);
	za = zfshandle_anon_find(zh->zh_pool_guid, zh->zh_ds_guid);
	KASSERT(za != NULL && za->za_mp == mp, ("anon mount lost its entry"));
	za->za_refs++;
	mtx_unlock(&zfshandle_anon_mtx);

	error = finstall(td, fp, &fd, O_CLOEXEC, NULL);
	fdrop(fp, td);
	if (error != 0)
		goto release;

	mutex_enter(&zh->zh_lock);
	zh->zh_anon_mp = mp;
	zh->zh_anon_mounting = B_FALSE;
	mutex_exit(&zh->zh_lock);

	SDT_PROBE3(trustedzfs, , , op__entry, zh->zh_ds_guid,
	    (int)ZFD_MOUNT, zh->zh_rights);
	args->zm_fd = fd;
	return (0);

release:
	/* Drop this handle's anchor: unmounts only if it was the last one. */
	zfshandle_anon_release(mp, td);
failed:
	mutex_enter(&zh->zh_lock);
	zh->zh_anon_mounting = B_FALSE;
	mutex_exit(&zh->zh_lock);
	return (error);
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

/*
 * These verbs normally share the namespace gate with other reads and legacy
 * ioctls. This excludes typed writers, but does not exclude legacy namespace
 * mutations. A policy requiring live ancestry requests exclusive retry before
 * the dispatcher permits the read. Exact-identity-only checks retain the
 * concurrent path. Mutations and handle derivation start exclusive.
 */

static boolean_t
zfshandle_cmd_is_read(u_long cmd)
{
	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
	case ZFD_INFO:
	case ZFD_STAT:
	case ZFD_GET_PROPS:
	case ZFD_GET_ONE_PROP:
	case ZFD_LIST_CHILDREN:
	case ZFD_LIST_SNAPS:
	case ZPD_STAT:
	case ZPD_GET_PROPS:
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
}

static int
zfshandle_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
	zfshandle_t *zh = fp->f_data;
	zfd_opset_t op;
	uint64_t right;
	boolean_t shared;

	int error;

	/*
	 * Read-only verbs take the namespace gate shared so they run concurrently;
	 * every mutating verb takes it exclusive (the object-to-name gate).
	 */
	shared = zfshandle_cmd_is_read(cmd);
	if (shared)
		sx_slock(&zfshandle_namespace_sx);
	else
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
	op = zfd_command_operation(cmd);
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
			error = zfshandle_op_rename(zh, data, active_cred);
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
	if (shared)
		sx_sunlock(&zfshandle_namespace_sx);
	else
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
