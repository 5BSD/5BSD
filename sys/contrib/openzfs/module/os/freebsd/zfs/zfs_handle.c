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
 * name-based ioctls use.  The guid witness closes the rename race up to the
 * final call; verbs that take a name (snapshot, rollback, props) retain a
 * tiny resolve-to-call window that a Phase 2 hold-by-obj variant of those
 * entry points would eliminate.
 */

#include <sys/types.h>
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
#include <sys/ucred.h>
#include <sys/user.h>
#include <sys/zfshandle.h>
#include <sys/zone.h>

#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_deleg.h>
#include <sys/dsl_destroy.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_scan.h>
#include <sys/freebsd_event.h>
#include <sys/metaslab.h>
#include <sys/fs/zfs.h>
#include <sys/spa.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_ioctl_impl.h>
#include <sys/zvol.h>

#include "zfs_namecheck.h"

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

/* Internal handle flag: this handle denotes a pool, not a dataset. */
#define	ZHF_POOL		0x40000000

typedef struct zfshandle {
	uint64_t	zh_pool_guid;
	uint64_t	zh_dsobj;
	uint64_t	zh_ds_guid;
	uint64_t	zh_rights;
	uint32_t	zh_flags;
	boolean_t	zh_invalid;
	kmutex_t	zh_lock;		/* struct sx underneath */
	struct selinfo	zh_sel;
	struct mount	*zh_anon_mp;		/* anonymous mount anchor */
	char		zh_name[ZFSHANDLE_NAME_MAX]; /* last resolved name */
} zfshandle_t;

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

static void
zfshandle_free(zfshandle_t *zh)
{
	seldrain(&zh->zh_sel);
	knlist_clear(&zh->zh_sel.si_note, 0);
	knlist_destroy(&zh->zh_sel.si_note);
	mutex_destroy(&zh->zh_lock);
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
	mutex_init(&zh->zh_lock, "zfshandle", MUTEX_DEFAULT, NULL);
	knlist_init_sx(&zh->zh_sel.si_note, &zh->zh_lock);
	(void) strlcpy(zh->zh_name, name, sizeof (zh->zh_name));
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

	if (zh->zh_invalid)
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
	error = finstall(td, fp, &fd, 0, NULL);
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
	{ ZH_ROLLBACK,		ZFS_DELEG_PERM_ROLLBACK },
	{ ZH_CLONE_SRC,		ZFS_DELEG_PERM_CLONE },
	{ ZH_CREATE,		ZFS_DELEG_PERM_CREATE },
	{ ZH_DESTROY,		ZFS_DELEG_PERM_DESTROY },
	{ ZH_SEND,		ZFS_DELEG_PERM_SEND },
	{ ZH_RECV,		ZFS_DELEG_PERM_RECEIVE },
	{ ZH_MOUNT,		ZFS_DELEG_PERM_MOUNT },
	{ ZH_HOLD,		ZFS_DELEG_PERM_HOLD },
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
	if (args->zgp_buflen < size)
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

	args->zsp_name[sizeof (args->zsp_name) - 1] = '\0';
	args->zsp_strval[sizeof (args->zsp_strval) - 1] = '\0';
	if (args->zsp_name[0] == '\0')
		return (SET_ERROR(EINVAL));
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
	    (args->zr_flags & ~ZHF_SUBTREE) != 0)
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

	(void) strlcpy(name, args->zpo_name, sizeof (name));
	if (name[0] == '\0' || strchr(name, '/') != NULL ||
	    strchr(name, '@') != NULL ||
	    pool_namecheck(name, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zpo_rights & ~(ZH_PROPS_READ | ZH_PROPS_WRITE |
	    ZH_SCRUB | ZH_EVENT | ZH_ALL_RIGHTS)) != 0)
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

	(void) strlcpy(name, args->zdo_name, sizeof (name));
	if (name[0] == '\0' ||
	    entity_namecheck(name, NULL, NULL) != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zdo_rights & ~ZH_ALL_RIGHTS) != 0 ||
	    (args->zdo_flags & ~ZHF_SUBTREE) != 0)
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
	args->zi_flags = zh->zh_flags;
	if (zh->zh_flags & ZHF_POOL) {
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
	if (args->zgp_buflen < size)
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

	args->zsp_name[sizeof (args->zsp_name) - 1] = '\0';
	args->zsp_strval[sizeof (args->zsp_strval) - 1] = '\0';
	if (args->zsp_name[0] == '\0')
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
zfshandle_op_snapshot(zfshandle_t *zh, struct zfd_snapshot_args *args)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *snaps;
	int error;

	args->zsn_snapname[sizeof (args->zsn_snapname) - 1] = '\0';
	error = zfshandle_snapname(zh, args->zsn_snapname, full,
	    sizeof (full));
	if (error != 0)
		return (error);

	snaps = fnvlist_alloc();
	fnvlist_add_boolean(snaps, full);
	error = dsl_dataset_snapshot(snaps, NULL, NULL);
	nvlist_free(snaps);
	return (error);
}

static int
zfshandle_op_snap_destroy(zfshandle_t *zh, struct zfd_snapshot_args *args)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	args->zsn_snapname[sizeof (args->zsn_snapname) - 1] = '\0';
	error = zfshandle_snapname(zh, args->zsn_snapname, full,
	    sizeof (full));
	if (error != 0)
		return (error);
	return (dsl_destroy_snapshot(full, B_FALSE));
}

static int
zfshandle_op_rollback(zfshandle_t *zh, struct zfd_rollback_args *args)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	char target[ZFS_MAX_DATASET_NAME_LEN];
	const char *tgt = NULL;
	zfsvfs_t *zfsvfs;
	zvol_state_handle_t *zv;
	nvlist_t *outnvl;
	int error;

	args->zr_snapname[sizeof (args->zr_snapname) - 1] = '\0';
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

	if ((args->zd_rights & ~ZH_ALL_RIGHTS) != 0)
		return (SET_ERROR(EINVAL));
	if ((args->zd_rights & ~zh->zh_rights) != 0)
		return (SET_ERROR(ENOTCAPABLE));

	mutex_enter(&zh->zh_lock);
	nzh = zfshandle_alloc(zh->zh_pool_guid, zh->zh_dsobj, zh->zh_ds_guid,
	    args->zd_rights, zh->zh_flags, zh->zh_name);
	mutex_exit(&zh->zh_lock);

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
	int error, fd;

	args->zo_relname[sizeof (args->zo_relname) - 1] = '\0';
	if (args->zo_relname[0] == '\0' || args->zo_relname[0] == '/' ||
	    strstr(args->zo_relname, "..") != NULL)
		return (SET_ERROR(EINVAL));
	if ((args->zo_rights & ~ZH_ALL_RIGHTS) != 0 ||
	    (args->zo_flags & ~ZHF_SUBTREE) != 0)
		return (SET_ERROR(EINVAL));
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
	    args->zo_rights, args->zo_flags, full);
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
	if (relname[0] == '/' || strstr(relname, "..") != NULL)
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
	int error, fd;

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
	    flags, full);
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

	args->zc_relname[sizeof (args->zc_relname) - 1] = '\0';
	if (args->zc_relname[0] == '\0' ||
	    strchr(args->zc_relname, '@') != NULL)
		return (SET_ERROR(EINVAL));
	if (args->zc_type != ZFD_TYPE_FILESYSTEM &&
	    args->zc_type != ZFD_TYPE_VOLUME)
		return (SET_ERROR(EINVAL));
	if ((args->zc_handle_flags & ~ZHF_SUBTREE) != 0)
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

	return (zfshandle_mint_child(td, zh, full, zh->zh_rights,
	    args->zc_handle_flags, &args->zc_fd));
}

static int
zfshandle_op_destroy(zfshandle_t *zh, struct zfd_destroy_args *args)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	args->zd_relname[sizeof (args->zd_relname) - 1] = '\0';
	if (strchr(args->zd_relname, '@') != NULL)
		return (SET_ERROR(EINVAL));
	error = zfshandle_relname(zh, args->zd_relname, B_TRUE, full,
	    sizeof (full));
	if (error != 0)
		return (error);
	return (zfshandle_ioc(ZFS_IOC_DESTROY, full, NULL, 0, NULL, NULL));
}

static int
zfshandle_op_rename(zfshandle_t *zh, struct zfd_rename_args *args)
{
	char from[ZFS_MAX_DATASET_NAME_LEN];
	char to[ZFS_MAX_DATASET_NAME_LEN];
	int error;

	args->zr_from[sizeof (args->zr_from) - 1] = '\0';
	args->zr_to[sizeof (args->zr_to) - 1] = '\0';
	if (args->zr_to[0] == '\0' || strchr(args->zr_to, '@') != NULL ||
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
	error = zfshandle_relname(zh, args->zr_to,
	    (zh->zh_flags & ZHF_SUBTREE) == 0, to, sizeof (to));
	if (error != 0)
		return (error);
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

	args->zc_relname[sizeof (args->zc_relname) - 1] = '\0';
	args->zc_origin_snap[sizeof (args->zc_origin_snap) - 1] = '\0';
	if (args->zc_relname[0] == '\0' ||
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

	return (zfshandle_mint_child(td, zh, full, zh->zh_rights, 0,
	    &args->zc_fd));
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
zfshandle_op_send(zfshandle_t *zh, struct zfd_send_args *args)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char from[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl;
	int error;

	args->zs_snapname[sizeof (args->zs_snapname) - 1] = '\0';
	args->zs_fromsnap[sizeof (args->zs_fromsnap) - 1] = '\0';
	error = zfshandle_snapref(zh, args->zs_snapname, full,
	    sizeof (full));
	if (error != 0)
		return (error);

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

	error = zfshandle_ioc(ZFS_IOC_SEND_NEW, full, NULL, 0, innvl, NULL);
	nvlist_free(innvl);
	return (error);
}

static int
zfshandle_op_recv(zfshandle_t *zh, struct zfd_recv_args *args)
{
	char full[ZFS_MAX_DATASET_NAME_LEN];
	char fsname[ZFS_MAX_DATASET_NAME_LEN];
	nvlist_t *innvl;
	char *at;
	int error;

	args->zr_reltarget[sizeof (args->zr_reltarget) - 1] = '\0';
	if (strchr(args->zr_reltarget, '@') == NULL)
		return (SET_ERROR(EINVAL));
	error = zfshandle_relname(zh, args->zr_reltarget, B_FALSE, full,
	    sizeof (full));
	if (error != 0)
		return (error);
	(void) strlcpy(fsname, full, sizeof (fsname));
	at = strchr(fsname, '@');
	*at = '\0';

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

	args->zh_snapname[sizeof (args->zh_snapname) - 1] = '\0';
	args->zh_tag[sizeof (args->zh_tag) - 1] = '\0';
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

	error = finstall(td, fp, &fd, flags, NULL);
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

	mp = vfs_mount_alloc(NULL, vfsp, fspath, td->td_ucred);
	mp->mnt_optnew = opts;
	if (rdonly)
		mp->mnt_flag |= MNT_RDONLY;

	error = VFS_MOUNT(mp);
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

	mutex_enter(&zh->zh_lock);
	if (zh->zh_anon_mp != NULL) {
		mutex_exit(&zh->zh_lock);
		return (SET_ERROR(EBUSY));
	}
	mutex_exit(&zh->zh_lock);

	/* Only ZPL filesystems mount. */
	error = zfshandle_hold(zh, FTAG, &dp, &ds);
	if (error != 0)
		return (error);
	error = dmu_objset_from_ds(ds, &os);
	if (error == 0 && dmu_objset_type(os) != DMU_OST_ZFS)
		error = SET_ERROR(EINVAL);
	dsl_dataset_name(ds, name);
	zfshandle_rele(dp, ds, FTAG);
	if (error != 0)
		return (error);

	error = zfshandle_anon_mount(td, name,
	    args->zm_rdonly ? B_TRUE : B_FALSE, &mp);
	if (error != 0)
		return (error);

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

	error = finstall(td, fp, &fd, 0, NULL);
	fdrop(fp, td);
	if (error != 0)
		goto unmount;

	/* The handle anchors the mount; hold the kern_unmount-style ref. */
	vfs_ref(mp);
	mutex_enter(&zh->zh_lock);
	zh->zh_anon_mp = mp;
	mutex_exit(&zh->zh_lock);

	SDT_PROBE3(trustedzfs, , , op__entry, zh->zh_ds_guid,
	    (int)ZFD_MOUNT, zh->zh_rights);
	args->zm_fd = fd;
	return (0);

unmount:
	vfs_ref(mp);		/* dounmount() consumes one reference */
	(void) dounmount(mp, MNT_FORCE, td);
	return (error);
}

static int
zfshandle_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
	zfshandle_t *zh = fp->f_data;
	int error;

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
		case ZPD_STAT:
		case ZPD_GET_PROPS:
		case ZPD_SET_PROP:
		case ZPD_SCRUB:
		case ZPD_ROOT_OPEN:
			break;
		default:
			SDT_PROBE3(trustedzfs, , , op__return,
			    zh->zh_ds_guid, (int)cmd, EINVAL);
			return (SET_ERROR(EINVAL));
		}
	} else {
		switch (cmd) {
		case ZPD_STAT:
		case ZPD_GET_PROPS:
		case ZPD_SET_PROP:
		case ZPD_SCRUB:
		case ZPD_ROOT_OPEN:
			SDT_PROBE3(trustedzfs, , , op__return,
			    zh->zh_ds_guid, (int)cmd, EINVAL);
			return (SET_ERROR(EINVAL));
		default:
			break;
		}
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
			error = zfshandle_op_snapshot(zh, data);
		break;
	case ZFD_SNAP_DESTROY:
		error = zfshandle_require(zh, cmd, ZH_SNAP_DESTROY);
		if (error == 0)
			error = zfshandle_op_snap_destroy(zh, data);
		break;
	case ZFD_ROLLBACK:
		error = zfshandle_require(zh, cmd, ZH_ROLLBACK);
		if (error == 0)
			error = zfshandle_op_rollback(zh, data);
		break;
	case ZFD_CREATE:
		error = zfshandle_require(zh, cmd, ZH_CREATE);
		if (error == 0)
			error = zfshandle_op_create(zh, data, td);
		break;
	case ZFD_DESTROY:
		error = zfshandle_require(zh, cmd, ZH_DESTROY);
		if (error == 0)
			error = zfshandle_op_destroy(zh, data);
		break;
	case ZFD_RENAME:
		error = zfshandle_require(zh, cmd, ZH_CREATE | ZH_DESTROY);
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
			error = zfshandle_op_send(zh, data);
		break;
	case ZFD_RECV:
		error = zfshandle_require(zh, cmd, ZH_RECV);
		if (error == 0)
			error = zfshandle_op_recv(zh, data);
		break;
	case ZFD_HOLD:
		error = zfshandle_require(zh, cmd, ZH_HOLD);
		if (error == 0)
			error = zfshandle_op_hold(zh, data, B_TRUE);
		break;
	case ZFD_RELEASE:
		error = zfshandle_require(zh, cmd, ZH_HOLD);
		if (error == 0)
			error = zfshandle_op_hold(zh, data, B_FALSE);
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
			error = zh->zh_anon_mp == NULL ?
			    SET_ERROR(ENOENT) : 0;
			mutex_exit(&zh->zh_lock);
			if (error == 0)
				zfshandle_anon_unmount(zh, td);
		}
		break;
	default:
		error = SET_ERROR(ENOTTY);
		break;
	}

	SDT_PROBE3(trustedzfs, , , op__return, zh->zh_ds_guid, (int)cmd,
	    error);
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
	zfshandle_anon_unmount(zh, td);
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
	kif->kf_un.kf_zfshandle.kf_zh_flags = zh->zh_flags;
	kif->kf_un.kf_zfshandle.kf_zh_valid = zh->zh_invalid ? 0 : 1;
	mutex_enter(&zh->zh_lock);
	(void) strlcpy(kif->kf_path, zh->zh_name, sizeof (kif->kf_path));
	mutex_exit(&zh->zh_lock);
	return (0);
}
