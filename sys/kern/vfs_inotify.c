/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Klara, Inc.
 */

#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/caprights.h>
#include <sys/counter.h>
#include <sys/dirent.h>
#define	EXTERR_CATEGORY	EXTERR_CAT_INOTIFY
#include <sys/exterrvar.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/inotify.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/ktrace.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/refcount.h>
#include <sys/selinfo.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/syslimits.h>
#include <sys/sysproto.h>
#include <sys/taskqueue.h>
#include <sys/tree.h>
#include <sys/user.h>
#include <sys/vnode.h>

uint32_t inotify_rename_cookie;

/*
 * Open-path identities are independent of reclaimable name-cache entries.
 * A file reference owns the record; dup/fork and retained mappings share it.
 * The vnode hold protects storage until final file destruction.  The parent
 * use reference preserves the directory identity across unlink and rename.
 * Neither struct file nor the filesystem's private file data is extended.
 */
/* Directory edges are retained only when rmdir removes a needed ancestor. */
struct inotify_parent {
	LIST_ENTRY(inotify_parent) link;
	struct inotify_parent *parent, *free_next;
	struct vnode *vp;
	u_int refs;
	size_t namelen;
	char name[NAME_MAX + 1];
};

struct inotify_path {
	LIST_ENTRY(inotify_path) file_link;
	LIST_ENTRY(inotify_path) vnode_link;
	struct file *fp;
	struct vnode *vp, *dvp;
	struct inotify_parent *parent;
	size_t namelen;
	u_int vnode_bucket;
	bool unlinked;
	uint64_t generation;
	char name[NAME_MAX + 1];
};
#define INOTIFY_PATH_BUCKETS 256
static LIST_HEAD(, inotify_path) inotify_file_paths[INOTIFY_PATH_BUCKETS];
static LIST_HEAD(, inotify_path) inotify_vnode_paths[INOTIFY_PATH_BUCKETS];
static LIST_HEAD(, inotify_parent) inotify_parents[INOTIFY_PATH_BUCKETS];
static u_int inotify_parent_count;
static uint64_t inotify_parent_generation;
static struct mtx inotify_path_mtx;
MTX_SYSINIT(inotify_path_lock, &inotify_path_mtx, "inotify paths", MTX_DEF);
static MALLOC_DEFINE(M_INOTIFYPATH, "inotify paths", "open path identities");
static u_int inotify_path_count;

static u_int
inotify_path_bucket(const void *p)
{
	return (((uintptr_t)p >> 8) & (INOTIFY_PATH_BUCKETS - 1));
}

static struct inotify_parent *
inotify_parent_find(struct vnode *vp)
{
	struct inotify_parent *parent;

	mtx_assert(&inotify_path_mtx, MA_OWNED);
	LIST_FOREACH(parent, &inotify_parents[inotify_path_bucket(vp)], link)
		if (parent->vp == vp)
			return (parent);
	return (NULL);
}

/* The caller provides storage because allocation must not hold the mutex. */
static struct inotify_parent *
inotify_parent_get(struct vnode *vp, struct inotify_parent **spare)
{
	struct inotify_parent *parent;

	parent = inotify_parent_find(vp);
	if (parent == NULL) {
		parent = *spare;
		MPASS(parent != NULL);
		*spare = NULL;
		parent->vp = vp;
		vref(vp);
		LIST_INSERT_HEAD(&inotify_parents[inotify_path_bucket(vp)], parent, link);
		atomic_add_int(&inotify_parent_count, 1);
	}
	parent->refs++;
	return (parent);
}

static void
inotify_parent_put(struct inotify_parent *parent, struct inotify_parent **dead)
{
	struct inotify_parent *next;

	mtx_assert(&inotify_path_mtx, MA_OWNED);
	while (parent != NULL) {
		MPASS(parent->refs != 0);
		if (--parent->refs != 0)
			break;
		LIST_REMOVE(parent, link);
		atomic_subtract_int(&inotify_parent_count, 1);
		next = parent->parent;
		parent->free_next = *dead;
		*dead = parent;
		parent = next;
	}
}

static void
inotify_parent_free(struct inotify_parent *dead)
{
	struct inotify_parent *next;

	while (dead != NULL) {
		next = dead->free_next;
		vrele(dead->vp);
		free(dead, M_INOTIFYPATH);
		dead = next;
	}
}

static struct inotify_path *
inotify_path_find(struct file *fp)
{
	struct inotify_path *path;

	mtx_assert(&inotify_path_mtx, MA_OWNED);
	LIST_FOREACH(path, &inotify_file_paths[inotify_path_bucket(fp)], file_link)
		if (path->fp == fp)
			return (path);
	return (NULL);
}

void
vn_inotify_path_attach(struct file *fp, struct vnode *vp, struct vnode *dvp,
    struct componentname *cnp)
{
	struct inotify_path *path;
	struct inotify_parent *spare;
	struct vnode *realparent;
	struct componentname realcn;
	char realname[NAME_MAX + 1];
	size_t namelen;

	if (vn_inotify_path_has(fp) || dvp == NULL ||
	    (vp->v_type != VREG && vp->v_type != VDIR) ||
	    cnp->cn_namelen > NAME_MAX)
		return;
	/*
	 * A lookup ending at a mount root can return the cross-mount
	 * placeholder as ni_dvp.  It is not a real parent and must never
	 * reach vn_fullpath().  Leave this file untracked so procfs resolves
	 * the actual vnode, including its mount point, instead.
	 */
	if ((vn_irflag_read(dvp) & VIRF_CROSSMP) != 0)
		return;
	if (cnp->cn_namelen == 0 ||
	    (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') ||
	    (cnp->cn_namelen == 2 && cnp->cn_nameptr[0] == '.' &&
	    cnp->cn_nameptr[1] == '.')) {
		if (vp->v_type != VDIR)
			return;
		namelen = NAME_MAX;
		if (cache_parent_name(vp, &realparent, realname, &namelen) != 0) {
			/* Stacked filesystems may keep names only in their lower layer. */
			namelen = NAME_MAX;
			if (VOP_VPTOCNP(vp, &realparent, realname, &namelen) != 0)
				return;
			memmove(realname, realname + namelen, NAME_MAX - namelen);
			namelen = NAME_MAX - namelen;
			if (VN_IS_DOOMED(vp)) {
				vrele(realparent);
				return;
			}
		}
		if (realparent != vp && namelen != 0) {
			realcn = *cnp;
			realcn.cn_nameptr = realname;
			realcn.cn_namelen = namelen;
			vn_inotify_path_attach(fp, vp, realparent, &realcn);
		}
		vrele(realparent);
		return;
	}
	spare = malloc(sizeof(*spare), M_INOTIFYPATH, M_WAITOK | M_ZERO);
	path = malloc(sizeof(*path), M_INOTIFYPATH, M_WAITOK | M_ZERO);
	path->fp = fp;
	path->vp = vp;
	path->dvp = dvp;
	path->namelen = cnp->cn_namelen;
	path->vnode_bucket = inotify_path_bucket(vp->v_vnlock);
	memcpy(path->name, cnp->cn_nameptr, path->namelen);
	vhold(vp);
	vref(dvp);
	mtx_lock(&inotify_path_mtx);
	MPASS(inotify_path_find(fp) == NULL);
	path->parent = inotify_parent_get(dvp, &spare);
	LIST_INSERT_HEAD(&inotify_file_paths[inotify_path_bucket(fp)], path, file_link);
	LIST_INSERT_HEAD(&inotify_vnode_paths[path->vnode_bucket], path, vnode_link);
	atomic_add_int(&inotify_path_count, 1);
	vn_irflag_set_cond(vp, VIRF_INOTIFY_PATH);
	mtx_unlock(&inotify_path_mtx);
	free(spare, M_INOTIFYPATH);
}

bool
vn_inotify_path_has(struct file *fp)
{
	bool found;

	if (atomic_load_int(&inotify_path_count) == 0)
		return (false);
	mtx_lock(&inotify_path_mtx);
	found = inotify_path_find(fp) != NULL;
	mtx_unlock(&inotify_path_mtx);
	return (found);
}

/* Snapshot the opened name, then resolve its parent outside the registry lock. */
int
vn_inotify_path_readlink(struct file *fp, char **name, char **buffer)
{
	struct inotify_path *path;
	struct inotify_parent *ancestor;
	struct vnode *dvp;
	char *suffix, *tail, *parent, *parentbuf, *result;
	size_t left;
	uint64_t generation, parent_generation;
	bool changed;
	int error, len;

	suffix = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
retry:
	tail = suffix + MAXPATHLEN - 1;
	*tail = '\0';
	mtx_lock(&inotify_path_mtx);
	path = inotify_path_find(fp);
	if (path == NULL) {
		mtx_unlock(&inotify_path_mtx);
		free(suffix, M_TEMP);
		return (EOPNOTSUPP);
	}
	if (path->unlinked) {
		tail -= sizeof(" (deleted)") - 1;
		memcpy(tail, " (deleted)", sizeof(" (deleted)") - 1);
	}
	tail -= path->namelen;
	memcpy(tail, path->name, path->namelen);
	*--tail = '/';
	ancestor = path->parent;
	while (ancestor->parent != NULL) {
		left = tail - suffix;
		if (left < ancestor->namelen + 1) {
			mtx_unlock(&inotify_path_mtx);
			free(suffix, M_TEMP);
			return (ENAMETOOLONG);
		}
		tail -= ancestor->namelen;
		memcpy(tail, ancestor->name, ancestor->namelen);
		*--tail = '/';
		ancestor = ancestor->parent;
	}
	generation = path->generation;
	parent_generation = inotify_parent_generation;
	dvp = ancestor->vp;
	vref(dvp);
	mtx_unlock(&inotify_path_mtx);
	error = vn_fullpath(dvp, &parent, &parentbuf);
	vrele(dvp);
	mtx_lock(&inotify_path_mtx);
	path = inotify_path_find(fp);
	MPASS(path != NULL); /* The caller holds the open description. */
	changed = generation != path->generation ||
	    parent_generation != inotify_parent_generation;
	mtx_unlock(&inotify_path_mtx);
	if (changed) {
		if (error == 0)
			free(parentbuf, M_TEMP);
		goto retry;
	}
	if (error != 0) {
		free(suffix, M_TEMP);
		return (error);
	}
	result = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	len = snprintf(result, MAXPATHLEN, "%s%s",
	    strcmp(parent, "/") == 0 ? "" : parent, tail);
	free(parentbuf, M_TEMP);
	free(suffix, M_TEMP);
	if (len >= MAXPATHLEN) {
		free(result, M_TEMP);
		return (ENAMETOOLONG);
	}
	*name = *buffer = result;
	return (0);
}

void
vn_inotify_path_drop(struct file *fp)
{
	struct inotify_path *path, *other;
	struct vnode *vp;
	struct inotify_parent *dead = NULL;

	if (atomic_load_int(&inotify_path_count) == 0)
		return;
	mtx_lock(&inotify_path_mtx);
	path = inotify_path_find(fp);
	if (path == NULL) {
		mtx_unlock(&inotify_path_mtx);
		return;
	}
	vp = path->vp;
	inotify_parent_put(path->parent, &dead);
	LIST_REMOVE(path, file_link);
	LIST_REMOVE(path, vnode_link);
	atomic_subtract_int(&inotify_path_count, 1);
	LIST_FOREACH(other, &inotify_vnode_paths[path->vnode_bucket], vnode_link)
		if (other->vp == vp)
			break;
	if (other == NULL)
		vn_irflag_unset(vp, VIRF_INOTIFY_PATH);
	mtx_unlock(&inotify_path_mtx);
	inotify_parent_free(dead);
	vrele(path->dvp);
	vdrop(vp);
	free(path, M_INOTIFYPATH);
}

/* A proc-fd magic link opens the source description's dentry independently. */
void
vn_inotify_path_copy(struct file *source)
{
	struct vn_file_context *ctx = vn_file_context_current();
	struct inotify_path *path, *original;

	if (ctx == NULL || ctx->fp == NULL || ctx->fp == source ||
	    SV_PROC_ABI(curproc) != SV_ABI_LINUX ||
	    (curproc->p_sysent->sv_flags & SV_LP64) == 0)
		return;
	path = malloc(sizeof(*path), M_INOTIFYPATH, M_WAITOK | M_ZERO);
	mtx_lock(&inotify_path_mtx);
	original = inotify_path_find(source);
	if (original == NULL || inotify_path_find(ctx->fp) != NULL) {
		mtx_unlock(&inotify_path_mtx);
		free(path, M_INOTIFYPATH);
		return;
	}
	path->fp = ctx->fp;
	path->vp = original->vp;
	path->dvp = original->dvp;
	path->parent = original->parent;
	path->parent->refs++;
	path->namelen = original->namelen;
	path->unlinked = original->unlinked;
	path->vnode_bucket = original->vnode_bucket;
	memcpy(path->name, original->name, path->namelen + 1);
	vhold(path->vp);
	vrefact(path->dvp);
	LIST_INSERT_HEAD(&inotify_file_paths[inotify_path_bucket(path->fp)], path, file_link);
	LIST_INSERT_HEAD(&inotify_vnode_paths[path->vnode_bucket], path, vnode_link);
	atomic_add_int(&inotify_path_count, 1);
	mtx_unlock(&inotify_path_mtx);
}

static bool
inotify_path_matches(struct inotify_path *path, struct vnode *vp,
    struct vnode *dvp, struct componentname *cnp)
{
	return ((path->vp == vp || (!VN_IS_DOOMED(path->vp) &&
	    path->vp->v_vnlock == vp->v_vnlock)) &&
	    (path->dvp == dvp || (!VN_IS_DOOMED(path->dvp) &&
	    path->dvp->v_vnlock == dvp->v_vnlock)) && !path->unlinked &&
	    path->namelen == cnp->cn_namelen &&
	    memcmp(path->name, cnp->cn_nameptr, path->namelen) == 0);
}

void
vn_inotify_path_unlink(struct vnode *vp, struct vnode *dvp,
    struct componentname *cnp)
{
	struct inotify_path *path;
	struct inotify_parent *parent, *spare = NULL;

	if (atomic_load_int(&inotify_path_count) == 0)
		return;
	if (vp->v_type == VDIR && vp != dvp)
		spare = malloc(sizeof(*spare), M_INOTIFYPATH, M_WAITOK | M_ZERO);
	mtx_lock(&inotify_path_mtx);
	parent = inotify_parent_find(vp);
	if (parent != NULL && parent->parent == NULL && spare != NULL) {
		parent->parent = inotify_parent_get(dvp, &spare);
		inotify_parent_generation++;
		parent->namelen = cnp->cn_namelen;
		memcpy(parent->name, cnp->cn_nameptr, parent->namelen);
		parent->name[parent->namelen] = '\0';
	}
	LIST_FOREACH(path, &inotify_vnode_paths[inotify_path_bucket(vp->v_vnlock)], vnode_link)
		if (inotify_path_matches(path, vp, dvp, cnp)) {
			path->unlinked = true;
			path->generation++;
		}
	mtx_unlock(&inotify_path_mtx);
	free(spare, M_INOTIFYPATH);
}

void
vn_inotify_path_rename(struct vnode *fvp, struct vnode *fdvp,
    struct componentname *fcnp, struct vnode *tvp, struct vnode *tdvp,
    struct componentname *tcnp)
{
	struct inotify_path *path;
	struct inotify_parent *spare = NULL, *dead = NULL;
	struct vnode **parents = NULL;
	size_t capacity = 0, count, releases;
	u_int bucket;

	if (fvp == tvp)
		return;
	if (tvp != NULL)
		vn_inotify_path_unlink(tvp, tdvp, tcnp);
	if (atomic_load_int(&inotify_path_count) == 0)
		return;
	if (fdvp != tdvp)
		spare = malloc(sizeof(*spare), M_INOTIFYPATH, M_WAITOK | M_ZERO);
	bucket = inotify_path_bucket(fvp->v_vnlock);
retry:
	mtx_lock(&inotify_path_mtx);
	count = 0;
	if (fdvp != tdvp) {
		LIST_FOREACH(path, &inotify_vnode_paths[bucket], vnode_link)
			if (path->dvp == fdvp &&
			    inotify_path_matches(path, fvp, fdvp, fcnp))
				count++;
	}
	if (count > capacity) {
		mtx_unlock(&inotify_path_mtx);
		free(parents, M_INOTIFYPATH);
		capacity = count + 8;
		parents = mallocarray(capacity, sizeof(*parents), M_INOTIFYPATH, M_WAITOK);
		goto retry;
	}
	releases = 0;
	LIST_FOREACH(path, &inotify_vnode_paths[bucket], vnode_link) {
		if (!inotify_path_matches(path, fvp, fdvp, fcnp))
			continue;
		/* Let the stacked post-hook supply the matching upper parent. */
		if (fdvp != tdvp && path->dvp != fdvp)
			continue;
		if (fdvp != tdvp) {
			/* The generic post-hook guarantees a hold, not a use reference. */
			vref(tdvp);
			parents[releases++] = path->dvp;
			path->dvp = tdvp;
			inotify_parent_put(path->parent, &dead);
			path->parent = inotify_parent_get(tdvp, &spare);
		}
		path->generation++;
		path->namelen = tcnp->cn_namelen;
		memcpy(path->name, tcnp->cn_nameptr, path->namelen);
		path->name[path->namelen] = '\0';
	}
	mtx_unlock(&inotify_path_mtx);
	while (releases != 0)
		vrele(parents[--releases]);
	free(parents, M_INOTIFYPATH);
	free(spare, M_INOTIFYPATH);
	inotify_parent_free(dead);
}

static SYSCTL_NODE(_vfs, OID_AUTO, inotify, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "inotify configuration");

SYSCTL_UINT(_vfs_inotify, OID_AUTO, paths, CTLFLAG_RD,
    &inotify_path_count, 0, "Number of retained open-path identities");

SYSCTL_UINT(_vfs_inotify, OID_AUTO, parents, CTLFLAG_RD,
    &inotify_parent_count, 0, "Number of retained parent directory identities");

static int inotify_max_queued_events = 16384;
SYSCTL_INT(_vfs_inotify, OID_AUTO, max_queued_events, CTLFLAG_RWTUN,
    &inotify_max_queued_events, 0,
    "Maximum number of events to queue on an inotify descriptor");

static int inotify_max_user_instances = 256;
SYSCTL_INT(_vfs_inotify, OID_AUTO, max_user_instances, CTLFLAG_RWTUN,
    &inotify_max_user_instances, 0,
    "Maximum number of inotify descriptors per user");

static int inotify_max_user_watches;
SYSCTL_INT(_vfs_inotify, OID_AUTO, max_user_watches, CTLFLAG_RWTUN,
    &inotify_max_user_watches, 0,
    "Maximum number of inotify watches per user");

static int inotify_max_watches;
SYSCTL_INT(_vfs_inotify, OID_AUTO, max_watches, CTLFLAG_RWTUN,
    &inotify_max_watches, 0,
    "Maximum number of inotify watches system-wide");

static int inotify_watches;
SYSCTL_INT(_vfs_inotify, OID_AUTO, watches, CTLFLAG_RD,
    &inotify_watches, 0,
    "Total number of inotify watches currently in use");

static int inotify_coalesce = 1;
SYSCTL_INT(_vfs_inotify, OID_AUTO, coalesce, CTLFLAG_RWTUN,
    &inotify_coalesce, 0,
    "Coalesce inotify events when possible");

static COUNTER_U64_DEFINE_EARLY(inotify_event_drops);
SYSCTL_COUNTER_U64(_vfs_inotify, OID_AUTO, event_drops, CTLFLAG_RD,
    &inotify_event_drops,
    "Number of inotify events dropped due to limits or allocation failures");

static fo_rdwr_t	inotify_read;
static fo_ioctl_t	inotify_ioctl;
static fo_poll_t	inotify_poll;
static fo_kqfilter_t	inotify_kqfilter;
static fo_stat_t	inotify_stat;
static fo_close_t	inotify_close;
static fo_fill_kinfo_t	inotify_fill_kinfo;

static const struct fileops inotifyfdops = {
	.fo_read = inotify_read,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = inotify_ioctl,
	.fo_poll = inotify_poll,
	.fo_kqfilter = inotify_kqfilter,
	.fo_stat = inotify_stat,
	.fo_close = inotify_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = inotify_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

static void	filt_inotifydetach(struct knote *kn);
static int	filt_inotifyevent(struct knote *kn, long hint);

static const struct filterops inotify_rfiltops = {
	.f_isfd = 1,
	.f_detach = filt_inotifydetach,
	.f_event = filt_inotifyevent,
	.f_copy = knote_triv_copy,
};

static MALLOC_DEFINE(M_INOTIFY, "inotify", "inotify data structures");

struct inotify_record {
	STAILQ_ENTRY(inotify_record) link;
	struct inotify_event	ev;
};

static uint64_t inotify_ino = 1;

struct inotify_watch {
	struct inotify_softc *sc; /* back-pointer */
	int		wd;	/* unique ID */
	uint32_t	mask;	/* event mask */
	struct vnode	*vp;	/* referenced, or held after final unlink */
	bool		unlinked; /* vpi_lock: owns a hold, not a use reference */
	RB_ENTRY(inotify_watch) ilink;		/* inotify linkage */
	TAILQ_ENTRY(inotify_watch) vlink;	/* vnode linkage */
};

static void
inotify_init(void *arg __unused)
{
	/* Don't let a user hold too many vnodes. */
	inotify_max_user_watches = desiredvnodes / 3;
	/* Don't let the system hold too many vnodes. */
	inotify_max_watches = desiredvnodes / 2;
}
SYSINIT(inotify, SI_SUB_VFS, SI_ORDER_ANY, inotify_init, NULL);

static int
inotify_watch_cmp(const struct inotify_watch *a,
    const struct inotify_watch *b)
{
	if (a->wd < b->wd)
		return (-1);
	else if (a->wd > b->wd)
		return (1);
	else
		return (0);
}
RB_HEAD(inotify_watch_tree, inotify_watch);
RB_GENERATE_STATIC(inotify_watch_tree, inotify_watch, ilink, inotify_watch_cmp);

struct inotify_softc {
	struct mtx	lock;			/* serialize all softc writes */
	STAILQ_HEAD(, inotify_record) pending;	/* events waiting to be read */
	struct inotify_record overflow;		/* preallocated record */
	int		nextwatch;		/* next watch ID to try */
	int		npending;		/* number of pending events */
	size_t		nbpending;		/* bytes available to read */
	uint64_t	ino;			/* unique identifier */
	bool		linux_abi;		/* event flag conventions */
	struct inotify_watch_tree watches;	/* active watches */
	TAILQ_HEAD(, inotify_watch) deadwatches; /* watches pending vrele() */
	struct task	reaptask;		/* task to reap dead watches */
	struct selinfo	sel;			/* select/poll/kevent info */
	struct ucred	*cred;			/* credential ref */
};

static struct inotify_record *
inotify_dequeue(struct inotify_softc *sc)
{
	struct inotify_record *rec;

	mtx_assert(&sc->lock, MA_OWNED);
	KASSERT(!STAILQ_EMPTY(&sc->pending),
	    ("%s: queue for %p is empty", __func__, sc));

	rec = STAILQ_FIRST(&sc->pending);
	STAILQ_REMOVE_HEAD(&sc->pending, link);
	sc->npending--;
	sc->nbpending -= sizeof(rec->ev) + rec->ev.len;
	return (rec);
}

static void
inotify_enqueue(struct inotify_softc *sc, struct inotify_record *rec, bool head)
{
	mtx_assert(&sc->lock, MA_OWNED);

	if (head)
		STAILQ_INSERT_HEAD(&sc->pending, rec, link);
	else
		STAILQ_INSERT_TAIL(&sc->pending, rec, link);
	sc->npending++;
	sc->nbpending += sizeof(rec->ev) + rec->ev.len;
}

static int
inotify_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags,
    struct thread *td)
{
	struct inotify_softc *sc;
	struct inotify_record *rec;
	int error;
	bool first;

	sc = fp->f_data;
	error = 0;

	mtx_lock(&sc->lock);
	while (STAILQ_EMPTY(&sc->pending)) {
		if ((flags & IO_NDELAY) != 0 || (fp->f_flag & FNONBLOCK) != 0) {
			mtx_unlock(&sc->lock);
			return (EWOULDBLOCK);
		}
		error = msleep(&sc->pending, &sc->lock, PCATCH, "inotify", 0);
		if (error != 0) {
			mtx_unlock(&sc->lock);
			return (error);
		}
	}
	for (first = true; !STAILQ_EMPTY(&sc->pending); first = false) {
		size_t len;

		rec = inotify_dequeue(sc);
		len = sizeof(rec->ev) + rec->ev.len;
		if (uio->uio_resid < (ssize_t)len) {
			inotify_enqueue(sc, rec, true);
			if (first) {
				error = EXTERROR(EINVAL,
				    "read buffer is too small");
			}
			break;
		}
		mtx_unlock(&sc->lock);
		error = uiomove(&rec->ev, len, uio);
#ifdef KTRACE
		if (error == 0 && KTRPOINT(td, KTR_STRUCT))
			ktrstruct("inotify", &rec->ev, len);
#endif
		mtx_lock(&sc->lock);
		if (error != 0) {
			inotify_enqueue(sc, rec, true);
			mtx_unlock(&sc->lock);
			return (error);
		}
		if (rec == &sc->overflow) {
			/*
			 * Signal to inotify_queue_record() that the overflow
			 * record can be reused.
			 */
			memset(rec, 0, sizeof(*rec));
		} else {
			free(rec, M_INOTIFY);
		}
	}
	mtx_unlock(&sc->lock);
	return (error);
}

static int
inotify_ioctl(struct file *fp, u_long com, void *data, struct ucred *cred,
    struct thread *td)
{
	struct inotify_softc *sc;

	sc = fp->f_data;

	switch (com) {
	case FIONREAD:
		mtx_lock(&sc->lock);
		*(int *)data = (int)sc->nbpending;
		mtx_unlock(&sc->lock);
		return (0);
	case FIONBIO:
	case FIOASYNC:
		return (0);
	default:
		return (ENOTTY);
	}

	return (0);
}

static int
inotify_poll(struct file *fp, int events, struct ucred *cred, struct thread *td)
{
	struct inotify_softc *sc;
	int revents;

	sc = fp->f_data;
	revents = 0;

	mtx_lock(&sc->lock);
	if ((events & (POLLIN | POLLRDNORM)) != 0 && sc->npending > 0)
		revents |= events & (POLLIN | POLLRDNORM);
	else
		selrecord(td, &sc->sel);
	mtx_unlock(&sc->lock);
	return (revents);
}

static void
filt_inotifydetach(struct knote *kn)
{
	struct inotify_softc *sc;

	sc = kn->kn_hook;
	knlist_remove(&sc->sel.si_note, kn, 0);
}

static int
filt_inotifyevent(struct knote *kn, long hint)
{
	struct inotify_softc *sc;

	sc = kn->kn_hook;
	mtx_assert(&sc->lock, MA_OWNED);
	kn->kn_data = sc->nbpending;
	return (kn->kn_data > 0);
}

static int
inotify_kqfilter(struct file *fp, struct knote *kn)
{
	struct inotify_softc *sc;

	if (kn->kn_filter != EVFILT_READ)
		return (EINVAL);
	sc = fp->f_data;
	kn->kn_fop = &inotify_rfiltops;
	kn->kn_hook = sc;
	knlist_add(&sc->sel.si_note, kn, 0);
	return (0);
}

static int
inotify_stat(struct file *fp, struct stat *sb, struct ucred *cred)
{
	struct inotify_softc *sc;

	sc = fp->f_data;

	memset(sb, 0, sizeof(*sb));
	sb->st_mode = S_IFREG | S_IRUSR;
	sb->st_blksize = sizeof(struct inotify_event) + _IN_NAMESIZE(NAME_MAX);
	mtx_lock(&sc->lock);
	sb->st_size = sc->nbpending;
	sb->st_blocks = sc->npending;
	sb->st_uid = sc->cred->cr_ruid;
	sb->st_gid = sc->cred->cr_rgid;
	sb->st_ino = sc->ino;
	mtx_unlock(&sc->lock);
	return (0);
}

static void
inotify_unlink_watch_locked(struct inotify_softc *sc, struct inotify_watch *watch)
{
	struct vnode *vp;

	vp = watch->vp;
	mtx_assert(&vp->v_pollinfo->vpi_lock, MA_OWNED);

	atomic_subtract_int(&inotify_watches, 1);
	(void)chginotifywatchcnt(sc->cred->cr_ruidinfo, -1, 0);

	TAILQ_REMOVE(&vp->v_pollinfo->vpi_inotify, watch, vlink);
	if (TAILQ_EMPTY(&vp->v_pollinfo->vpi_inotify))
		vn_irflag_unset(vp, VIRF_INOTIFY);
}

static void
inotify_free_watch(struct inotify_watch *watch)
{
	/*
	 * Formally, we don't need to lock the vnode here.  However, if we
	 * don't, and vrele() releases the last reference, it's possible the
	 * vnode will be recycled while a different thread holds the vnode lock.
	 * Work around this bug by acquiring the lock here.
	 */
	(void)vn_lock(watch->vp, LK_EXCLUSIVE | LK_RETRY);
	if (watch->unlinked) {
		VOP_UNLOCK(watch->vp);
		vdrop(watch->vp);
	} else {
		vput(watch->vp);
	}
	free(watch, M_INOTIFY);
}

/*
 * Assumes that the watch has already been removed from its softc.
 */
static void
inotify_remove_watch(struct inotify_watch *watch)
{
	struct inotify_softc *sc;
	struct vnode *vp;

	sc = watch->sc;

	vp = watch->vp;
	mtx_lock(&vp->v_pollinfo->vpi_lock);
	inotify_unlink_watch_locked(sc, watch);
	mtx_unlock(&vp->v_pollinfo->vpi_lock);
	inotify_free_watch(watch);
}

static void
inotify_reap(void *arg, int pending)
{
	struct inotify_softc *sc;
	struct inotify_watch *watch;

	sc = arg;
	mtx_lock(&sc->lock);
	while ((watch = TAILQ_FIRST(&sc->deadwatches)) != NULL) {
		TAILQ_REMOVE(&sc->deadwatches, watch, vlink);
		mtx_unlock(&sc->lock);
		inotify_free_watch(watch);
		mtx_lock(&sc->lock);
	}
	mtx_unlock(&sc->lock);
}

static int
inotify_close(struct file *fp, struct thread *td)
{
	struct inotify_softc *sc;
	struct inotify_record *rec;
	struct inotify_watch *watch;

	sc = fp->f_data;

	/* Detach watches from their vnodes. */
	mtx_lock(&sc->lock);
	(void)chginotifycnt(sc->cred->cr_ruidinfo, -1, 0);
	while ((watch = RB_MIN(inotify_watch_tree, &sc->watches)) != NULL) {
		RB_REMOVE(inotify_watch_tree, &sc->watches, watch);
		mtx_unlock(&sc->lock);
		inotify_remove_watch(watch);
		mtx_lock(&sc->lock);
	}

	/* Make sure that any asynchronous vrele() calls are done. */
	mtx_unlock(&sc->lock);
	taskqueue_drain(taskqueue_thread, &sc->reaptask);
	mtx_lock(&sc->lock);
	KASSERT(RB_EMPTY(&sc->watches),
	    ("%s: watches not empty in %p", __func__, sc));
	KASSERT(TAILQ_EMPTY(&sc->deadwatches),
	    ("%s: deadwatches not empty in %p", __func__, sc));

	/* Drop pending events. */
	while (!STAILQ_EMPTY(&sc->pending)) {
		rec = inotify_dequeue(sc);
		if (rec != &sc->overflow)
			free(rec, M_INOTIFY);
	}
	mtx_unlock(&sc->lock);
	seldrain(&sc->sel);
	knlist_destroy(&sc->sel.si_note);
	mtx_destroy(&sc->lock);
	crfree(sc->cred);
	free(sc, M_INOTIFY);
	return (0);
}

static int
inotify_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{
	struct inotify_softc *sc;

	sc = fp->f_data;

	mtx_lock(&sc->lock);
	kif->kf_type = KF_TYPE_INOTIFY;
	kif->kf_un.kf_inotify.kf_inotify_npending = sc->npending;
	kif->kf_un.kf_inotify.kf_inotify_nbpending = sc->nbpending;
	mtx_unlock(&sc->lock);
	return (0);
}

int
inotify_create_file(struct thread *td, struct file *fp, int flags, int *fflagsp)
{
	struct inotify_softc *sc;
	int fflags;

	if ((flags & ~(IN_NONBLOCK | IN_CLOEXEC)) != 0)
		return (EINVAL);

	if (!chginotifycnt(td->td_ucred->cr_ruidinfo, 1,
	    inotify_max_user_instances))
		return (EMFILE);

	sc = malloc(sizeof(*sc), M_INOTIFY, M_WAITOK | M_ZERO);
	sc->nextwatch = 1; /* Required for compatibility. */
	STAILQ_INIT(&sc->pending);
	RB_INIT(&sc->watches);
	TAILQ_INIT(&sc->deadwatches);
	TASK_INIT(&sc->reaptask, 0, inotify_reap, sc);
	mtx_init(&sc->lock, "inotify", NULL, MTX_DEF);
	knlist_init_mtx(&sc->sel.si_note, &sc->lock);
	sc->cred = crhold(td->td_ucred);
	sc->linux_abi = SV_PROC_ABI(td->td_proc) == SV_ABI_LINUX;
	sc->ino = atomic_fetchadd_64(&inotify_ino, 1);

	fflags = FREAD;
	if ((flags & IN_NONBLOCK) != 0)
		fflags |= FNONBLOCK;
	if ((flags & IN_CLOEXEC) != 0)
		*fflagsp |= O_CLOEXEC;
	finit(fp, fflags, DTYPE_INOTIFY, sc, &inotifyfdops);

	return (0);
}

static struct inotify_record *
inotify_alloc_record(uint32_t wd, const char *name, size_t namelen, int event,
    uint32_t cookie, int waitok)
{
	struct inotify_event *evp;
	struct inotify_record *rec;

	rec = malloc(sizeof(*rec) + _IN_NAMESIZE(namelen), M_INOTIFY,
	    waitok | M_ZERO);
	if (rec == NULL)
		return (NULL);
	evp = &rec->ev;
	evp->wd = wd;
	evp->mask = event;
	evp->cookie = cookie;
	evp->len = _IN_NAMESIZE(namelen);
	if (name != NULL)
		memcpy(evp->name, name, namelen);
	return (rec);
}

static bool
inotify_can_coalesce(struct inotify_softc *sc, struct inotify_event *evp)
{
	struct inotify_record *prev;

	mtx_assert(&sc->lock, MA_OWNED);

	prev = STAILQ_LAST(&sc->pending, inotify_record, link);
	return (prev != NULL && prev->ev.mask == evp->mask &&
	    prev->ev.wd == evp->wd && prev->ev.cookie == evp->cookie &&
	    prev->ev.len == evp->len &&
	    memcmp(prev->ev.name, evp->name, evp->len) == 0);
}

static void
inotify_overflow_event(struct inotify_event *evp)
{
	evp->mask = IN_Q_OVERFLOW;
	evp->wd = -1;
	evp->cookie = 0;
	evp->len = 0;
}

/*
 * Put an event record on the queue for an inotify desscriptor.  Return false if
 * the record was not enqueued for some reason, true otherwise.
 */
static bool
inotify_queue_record(struct inotify_softc *sc, struct inotify_record *rec)
{
	struct inotify_event *evp;

	mtx_assert(&sc->lock, MA_OWNED);

	evp = &rec->ev;
	if (__predict_false(rec == &sc->overflow)) {
		/*
		 * Is the overflow record already in the queue?  If so, there's
		 * not much else we can do: we're here because a kernel memory
		 * shortage prevented new record allocations.
		 */
		counter_u64_add(inotify_event_drops, 1);
		if (evp->mask == IN_Q_OVERFLOW)
			return (false);
		inotify_overflow_event(evp);
	} else {
		/* Try to coalesce duplicate events. */
		if (inotify_coalesce && inotify_can_coalesce(sc, evp))
			return (false);

		/*
		 * Would this one overflow the queue?  If so, convert it to an
		 * overflow event and try again to coalesce.
		 */
		if (sc->npending >= inotify_max_queued_events) {
			counter_u64_add(inotify_event_drops, 1);
			inotify_overflow_event(evp);
			if (inotify_can_coalesce(sc, evp))
				return (false);
		}
	}
	inotify_enqueue(sc, rec, false);
	selwakeup(&sc->sel);
	KNOTE_LOCKED(&sc->sel.si_note, 0);
	wakeup(&sc->pending);
	return (true);
}

static void
inotify_log_one(struct inotify_watch *watch, const char *name, size_t namelen,
    int event, uint32_t cookie)
{
	struct inotify_watch key;
	struct inotify_softc *sc;
	struct inotify_record *rec;
	bool allocfail;

	mtx_assert(&watch->vp->v_pollinfo->vpi_lock, MA_OWNED);

	sc = watch->sc;
	/* Linux does not attach IN_ISDIR to the terminal self-delete event. */
	if (sc->linux_abi && (event & IN_DELETE_SELF) != 0)
		event &= ~IN_ISDIR;
	allocfail = false;
	mtx_lock(&sc->lock);
	/* Deletion removes the watch even if DELETE_SELF was not requested. */
	if ((watch->mask & event) != 0 || event == IN_UNMOUNT) {
		rec = inotify_alloc_record(watch->wd, name, namelen, event,
		    cookie, M_NOWAIT);
		if (rec == NULL) {
			rec = &sc->overflow;
			allocfail = true;
		}
		if (!inotify_queue_record(sc, rec) && rec != &sc->overflow)
			free(rec, M_INOTIFY);
	}
	if ((watch->mask & IN_ONESHOT) != 0 ||
	    (event & (IN_DELETE_SELF | IN_UNMOUNT)) != 0) {
		if (!allocfail) {
			rec = inotify_alloc_record(watch->wd, NULL, 0,
			    IN_IGNORED, 0, M_NOWAIT);
			if (rec == NULL)
				rec = &sc->overflow;
			if (!inotify_queue_record(sc, rec) &&
			    rec != &sc->overflow)
				free(rec, M_INOTIFY);
		}

		/*
		 * Remove the watch, taking care to handle races with
		 * inotify_close().  The thread that removes the watch is
		 * responsible for freeing it.
		 */
		key.wd = watch->wd;
		if (RB_FIND(inotify_watch_tree, &sc->watches, &key) != NULL) {
			RB_REMOVE(inotify_watch_tree, &sc->watches, watch);
			inotify_unlink_watch_locked(sc, watch);

			/*
			 * Defer the vrele() to a sleepable thread context.
			 */
			TAILQ_INSERT_TAIL(&sc->deadwatches, watch, vlink);
			taskqueue_enqueue(taskqueue_thread, &sc->reaptask);
		}
	}
	mtx_unlock(&sc->lock);
}

static void
inotify_log_impl(struct vnode *vp, const char *name, size_t namelen, int event,
    uint32_t cookie, bool unlinked)
{
	struct inotify_watch *watch, *tmp;

	KASSERT((event & ~(IN_ALL_EVENTS | IN_ISDIR | IN_UNMOUNT)) == 0,
	    ("inotify_log: invalid event %#x", event));

	mtx_lock(&vp->v_pollinfo->vpi_lock);
	TAILQ_FOREACH_SAFE(watch, &vp->v_pollinfo->vpi_inotify, vlink, tmp) {
		KASSERT(watch->vp == vp,
		    ("inotify_log: watch %p vp != vp", watch));
		if (unlinked && (watch->mask & IN_EXCL_UNLINK) != 0)
			continue;
		if ((watch->mask & event) != 0 ||
		    (event & (IN_DELETE_SELF | IN_UNMOUNT)) != 0)
			inotify_log_one(watch, name, namelen, event, cookie);
	}
	mtx_unlock(&vp->v_pollinfo->vpi_lock);
}

void
inotify_log(struct vnode *vp, const char *name, size_t namelen, int event,
    uint32_t cookie)
{
	inotify_log_impl(vp, name, namelen, event, cookie, false);
}

/* Return true only when this operation has an exact open-path identity. */
bool
vn_inotify_file(struct vnode *vp, int event, uint32_t cookie)
{
	struct vn_file_context *ctx = vn_file_context_current();
	struct inotify_path *path;
	struct componentname cn = { 0 };
	struct vnode *dvp, *pathvp;
	char name[NAME_MAX + 1];

	if (ctx == NULL || (event & (IN_OPEN | IN_ACCESS | IN_MODIFY |
	    IN_CLOSE | IN_ATTRIB)) == 0)
		return (false);
	if (event == IN_ACCESS &&
	    (curthread->td_pflags2 & TDP2_INOTIFY_LOOKUP) != 0)
		return (true);
	mtx_lock(&inotify_path_mtx);
	path = inotify_path_find((event & IN_MODIFY) != 0 && ctx->fp2 != NULL ?
	    ctx->fp2 : ctx->fp);
	if (path == NULL || (path->vp != vp &&
	    (VN_IS_DOOMED(path->vp) || path->vp->v_vnlock != vp->v_vnlock))) {
		mtx_unlock(&inotify_path_mtx);
		return (false);
	}
	/* Ordinary layered VOPs notify again through their upper vnode. */
	if (path->vp != vp && ctx->fp2 == NULL) {
		mtx_unlock(&inotify_path_mtx);
		return (true);
	}
	pathvp = path->vp;
	dvp = path->dvp;
	vhold(dvp);
	cn.cn_nameptr = name;
	cn.cn_namelen = path->namelen;
	cn.cn_cred = path->fp->f_cred;
	memcpy(name, path->name, path->namelen + 1);
	event |= _IN_FILE_EVENT;
	if (path->unlinked)
		event |= _IN_FILE_UNLINKED;
	mtx_unlock(&inotify_path_mtx);
	/* Let layered filesystems translate both vnode identities together. */
	VOP_INOTIFY(pathvp, dvp, &cn, event, cookie);
	vdrop(dvp);
	return (true);
}

/*
 * Watches must not keep an unlinked object active.  Keep a hold on the vnode
 * storage instead, so final file/mapping release can run vinactive().  The
 * caller's reference and vnode lock prevent inactivation during conversion.
 */
static void
inotify_unlinked(struct vnode *vp)
{
	struct inotify_watch *watch;
	unsigned refs;

	ASSERT_VOP_LOCKED(vp, __func__);
	refs = 0;
	mtx_lock(&vp->v_pollinfo->vpi_lock);
	TAILQ_FOREACH(watch, &vp->v_pollinfo->vpi_inotify, vlink) {
		if (!watch->unlinked) {
			vhold(vp);
			watch->unlinked = true;
			refs++;
		}
	}
	mtx_unlock(&vp->v_pollinfo->vpi_lock);
	while (refs-- != 0)
		vrele(vp);
}

void
vn_inotify_inactive(struct vnode *vp)
{
	struct inotify_watch *watch, *tmp;
	int event;

	ASSERT_VOP_ELOCKED(vp, __func__);
	/* Nullfs may mirror the lower vnode's flag without owning watches. */
	if ((vn_irflag_read(vp) & VIRF_INOTIFY) == 0 ||
	    vp->v_pollinfo == NULL || refcount_load(&vp->v_usecount) != 0)
		return;
	event = IN_DELETE_SELF | (vp->v_type == VDIR ? IN_ISDIR : 0);
	mtx_lock(&vp->v_pollinfo->vpi_lock);
	TAILQ_FOREACH_SAFE(watch, &vp->v_pollinfo->vpi_inotify, vlink, tmp) {
		if (watch->unlinked)
			inotify_log_one(watch, NULL, 0, event, 0);
	}
	mtx_unlock(&vp->v_pollinfo->vpi_lock);
}

/*
 * An inotify event occurred on a watched vnode.
 */
void
vn_inotify(struct vnode *vp, struct vnode *dvp, struct componentname *cnp,
    int event, uint32_t cookie)
{
	int isdir;
	bool unlinked, file_event;

	unlinked = (event & _IN_FILE_UNLINKED) != 0;
	file_event = (event & _IN_FILE_EVENT) != 0;
	event &= ~(_IN_FILE_UNLINKED | _IN_FILE_EVENT);
	if (event == IN_ACCESS &&
	    (curthread->td_pflags2 & TDP2_INOTIFY_LOOKUP) != 0)
		return;
	VNPASS(vp->v_holdcnt > 0, vp);

	isdir = vp->v_type == VDIR ? IN_ISDIR : 0;

	if (dvp != NULL) {
		VNPASS(dvp->v_holdcnt > 0, dvp);

		/*
		 * Should we log an event for the vnode itself?
		 */
		if ((vn_irflag_read(vp) & VIRF_INOTIFY) != 0) {
			int selfevent;

			switch (event) {
			case _IN_MOVE_DELETE:
			case IN_DELETE:
				/*
				 * IN_DELETE_SELF is only generated when the
				 * last hard link of a file is removed.
				 */
				selfevent = IN_DELETE_SELF;
				if (vp->v_type != VDIR) {
					struct vattr va;
					int error;

					error = VOP_GETATTR(vp, &va,
					    cnp->cn_cred);
					if (error == 0 && va.va_nlink != 0)
						selfevent = 0;
				}
				break;
			case IN_MOVED_FROM:
				selfevent = IN_MOVE_SELF;
				break;
			case _IN_ATTRIB_LINKCOUNT:
				selfevent = IN_ATTRIB;
				break;
			default:
				selfevent = event;
				break;
			}

			if (selfevent == IN_DELETE_SELF) {
				inotify_unlinked(vp);
				selfevent = 0;
			}
			if ((selfevent & ~_IN_DIR_EVENTS) != 0 ||
			    (file_event && vp->v_type != VDIR && selfevent != 0))
				inotify_log(vp, NULL, 0, selfevent | isdir, 0);
		}

		/*
		 * Something is watching the directory through which this vnode
		 * was referenced, so we may need to log the event.
		 */
		if ((event & IN_ALL_EVENTS) != 0 &&
		    (vn_irflag_read(dvp) & VIRF_INOTIFY) != 0) {
			inotify_log_impl(dvp, cnp->cn_nameptr,
			    cnp->cn_namelen, event | isdir, cookie, unlinked);
		}
	} else {
		/*
		 * We don't know which watched directory might contain the
		 * vnode, so we have to fall back to searching the name cache.
		 */
		cache_vop_inotify(vp, event, cookie);
	}
}

int
vn_inotify_add_watch(struct vnode *vp, struct inotify_softc *sc, uint32_t mask,
    uint32_t *wdp, struct thread *td)
{
	struct inotify_watch *watch, *watch1;
	struct vattr va;
	uint32_t wd;
	int error;


	/*
	 * If this is a directory, make sure all of its entries are present in
	 * the name cache so that we're able to look them up if an event occurs.
	 * The persistent reference on the directory prevents the outgoing name
	 * cache entries from being reclaimed.
	 */
	if (vp->v_type == VDIR) {
		struct dirent *dp;
		char *buf;
		off_t off;
		size_t buflen, len;
		int eof, error, saved;

		buflen = 128 * sizeof(struct dirent);
		buf = malloc(buflen, M_TEMP, M_WAITOK);

		error = 0;
		len = off = eof = 0;
		for (;;) {
			struct nameidata nd;

			saved = curthread_pflags2_set(TDP2_INOTIFY_LOOKUP);
			error = vn_dir_next_dirent(vp, td, buf, buflen, &dp,
			    &len, &off, &eof);
			curthread_pflags2_restore(saved);
			if (error != 0)
				break;
			if (len == 0)
				/* Finished reading. */
				break;
			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0)
				continue;

			/*
			 * namei() consumes a reference on the starting
			 * directory if it's specified as a vnode.
			 */
			vrefact(vp);
			VOP_UNLOCK(vp);
			NDINIT_ATVP(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE,
			    dp->d_name, vp);
			error = namei(&nd);
			vn_lock(vp, LK_SHARED | LK_RETRY);
			/* A directory entry may disappear while its lock is dropped. */
			if (error == ENOENT) {
				error = 0;
				continue;
			}
			if (error != 0)
				break;
			NDFREE_PNBUF(&nd);
			vn_irflag_set_cond(nd.ni_vp, VIRF_INOTIFY_PARENT);
			vrele(nd.ni_vp);
		}
		free(buf, M_TEMP);
		if (error != 0)
			return (error);
	}

	/* A watch may be added through /proc to an already-unlinked vnode. */
	error = VOP_GETATTR(vp, &va, td->td_ucred);
	if (error != 0)
		return (error);

	/*
	 * The vnode referenced in kern_inotify_add_watch() might be different
	 * than this one if nullfs is in the picture.
	 */
	vrefact(vp);
	watch = malloc(sizeof(*watch), M_INOTIFY, M_WAITOK | M_ZERO);
	watch->sc = sc;
	watch->vp = vp;
	watch->mask = mask;

	/*
	 * Are we updating an existing watch?  Search the vnode's list rather
	 * than that of the softc, as the former is likely to be shorter.
	 */
	v_addpollinfo(vp);
	mtx_lock(&vp->v_pollinfo->vpi_lock);
	TAILQ_FOREACH(watch1, &vp->v_pollinfo->vpi_inotify, vlink) {
		if (watch1->sc == sc)
			break;
	}
	mtx_lock(&sc->lock);
	if (watch1 != NULL) {

		/*
		 * We found an existing watch, update it based on our flags.
		 */
		if ((mask & IN_MASK_CREATE) != 0) {
			mtx_unlock(&sc->lock);
			mtx_unlock(&vp->v_pollinfo->vpi_lock);
			vrele(vp);
			free(watch, M_INOTIFY);
			return (EEXIST);
		}
		if ((mask & IN_MASK_ADD) != 0)
			watch1->mask |= mask;
		else
			watch1->mask = mask;
		*wdp = watch1->wd;
		mtx_unlock(&sc->lock);
		mtx_unlock(&vp->v_pollinfo->vpi_lock);
		vrele(vp);
		free(watch, M_INOTIFY);
		return (EJUSTRETURN);
	}

	/*
	 * We're creating a new watch.  Add it to the softc and vnode watch
	 * lists.
	 */
	do {
		struct inotify_watch key;

		/*
		 * Search for the next available watch descriptor.  This is
		 * implemented so as to avoid reusing watch descriptors for as
		 * long as possible.
		 */
		key.wd = wd = sc->nextwatch++;
		watch1 = RB_FIND(inotify_watch_tree, &sc->watches, &key);
	} while (watch1 != NULL || wd == 0);
	watch->wd = wd;
	RB_INSERT(inotify_watch_tree, &sc->watches, watch);
	TAILQ_INSERT_TAIL(&vp->v_pollinfo->vpi_inotify, watch, vlink);
	mtx_unlock(&sc->lock);
	mtx_unlock(&vp->v_pollinfo->vpi_lock);
	vn_irflag_set_cond(vp, VIRF_INOTIFY);

	*wdp = wd;
	if (va.va_nlink == 0)
		inotify_unlinked(vp);

	return (0);
}

void
vn_inotify_revoke(struct vnode *vp)
{
	inotify_log(vp, NULL, 0, IN_UNMOUNT, 0);
}

static int
fget_inotify(struct thread *td, int fd, const cap_rights_t *needrightsp,
    struct file **fpp)
{
	struct file *fp;
	int error;

	error = fget(td, fd, needrightsp, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_INOTIFY) {
		fdrop(fp, td);
		return (EINVAL);
	}
	*fpp = fp;
	return (0);
}

int
kern_inotify_add_watch(int fd, int dfd, const char *path, uint32_t mask,
    struct thread *td)
{
	struct nameidata nd;
	struct file *fp;
	struct inotify_softc *sc;
	struct vnode *vp;
	uint32_t wd;
	int count, error;

	fp = NULL;
	vp = NULL;

	if ((mask & IN_ALL_EVENTS) == 0)
		return (EXTERROR(EINVAL, "no events specified"));
	if ((mask & (IN_MASK_ADD | IN_MASK_CREATE)) ==
	    (IN_MASK_ADD | IN_MASK_CREATE))
		return (EXTERROR(EINVAL,
		    "IN_MASK_ADD and IN_MASK_CREATE are mutually exclusive"));
	if ((mask & ~(IN_ALL_EVENTS | _IN_ALL_FLAGS | IN_UNMOUNT)) != 0)
		return (EXTERROR(EINVAL, "unrecognized flag"));

	error = fget_inotify(td, fd, &cap_inotify_add_rights, &fp);
	if (error != 0)
		return (error);
	sc = fp->f_data;

	NDINIT_AT(&nd, LOOKUP,
	    ((mask & IN_DONT_FOLLOW) ? NOFOLLOW : FOLLOW) | LOCKLEAF |
	    LOCKSHARED | AUDITVNODE1, UIO_USERSPACE, path, dfd);
	error = namei(&nd);
	if (error != 0)
		goto out;
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;

	error = VOP_ACCESS(vp, VREAD, td->td_ucred, td);
	if (error != 0)
		goto out;

	if ((mask & IN_ONLYDIR) != 0 && vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

	count = atomic_fetchadd_int(&inotify_watches, 1);
	if (count > inotify_max_watches) {
		atomic_subtract_int(&inotify_watches, 1);
		error = ENOSPC;
		goto out;
	}
	if (!chginotifywatchcnt(sc->cred->cr_ruidinfo, 1,
	    inotify_max_user_watches)) {
		atomic_subtract_int(&inotify_watches, 1);
		error = ENOSPC;
		goto out;
	}
	error = VOP_INOTIFY_ADD_WATCH(vp, sc, mask, &wd, td);
	if (error != 0) {
		atomic_subtract_int(&inotify_watches, 1);
		(void)chginotifywatchcnt(sc->cred->cr_ruidinfo, -1, 0);
		if (error == EJUSTRETURN) {
			/* We updated an existing watch, everything is ok. */
			error = 0;
		} else {
			goto out;
		}
	}
	td->td_retval[0] = wd;

out:
	if (vp != NULL)
		vput(vp);
	fdrop(fp, td);
	return (error);
}

int
sys_inotify_add_watch_at(struct thread *td,
    struct inotify_add_watch_at_args *uap)
{
	return (kern_inotify_add_watch(uap->fd, uap->dfd, uap->path,
	    uap->mask, td));
}

int
kern_inotify_rm_watch(int fd, uint32_t wd, struct thread *td)
{
	struct file *fp;
	struct inotify_softc *sc;
	struct inotify_record *rec;
	struct inotify_watch key, *watch;
	int error;

	error = fget_inotify(td, fd, &cap_inotify_rm_rights, &fp);
	if (error != 0)
		return (error);
	sc = fp->f_data;

	rec = inotify_alloc_record(wd, NULL, 0, IN_IGNORED, 0, M_WAITOK);

	/*
	 * For compatibility with Linux, we do not remove pending events
	 * associated with the watch.  Watch descriptors are implemented so as
	 * to avoid being reused for as long as possible, so one hopes that any
	 * pending events from the removed watch descriptor will be removed
	 * before the watch descriptor is recycled.
	 */
	key.wd = wd;
	mtx_lock(&sc->lock);
	watch = RB_FIND(inotify_watch_tree, &sc->watches, &key);
	if (watch == NULL) {
		free(rec, M_INOTIFY);
		error = EINVAL;
	} else {
		RB_REMOVE(inotify_watch_tree, &sc->watches, watch);
		if (!inotify_queue_record(sc, rec)) {
			free(rec, M_INOTIFY);
			error = 0;
		}
	}
	mtx_unlock(&sc->lock);
	if (watch != NULL)
		inotify_remove_watch(watch);
	fdrop(fp, td);
	return (error);
}

int
sys_inotify_rm_watch(struct thread *td, struct inotify_rm_watch_args *uap)
{
	return (kern_inotify_rm_watch(uap->fd, uap->wd, td));
}
