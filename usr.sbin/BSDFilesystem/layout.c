/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdfilesystem(8) layout provisioning.  bsdfilesystem is an ambient provider and never
 * cap_enter()s; everything here runs during startup: it
 * opens handles by name (tzfs_open needs /dev/zfs) and imports the pool.  The
 * retained parent handles are what the request loop uses in capability mode.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/linker.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <logcmp.h>
#include <time.h>
#include <unistd.h>

#include <trustedzfs.h>
#include <capreclaim.h>

#include "bsdfilesystem.h"
#include "bsdfilesystem_probes.h"

extern char **environ;

/*
 * The container-model live set (docs/book/src/plane/containers-and-storage.md): the
 * installed bundles are the pkg-owned System/ and Apps/ directories (read
 * directly -- they are always authoritative, so no marker or sentinel is
 * needed), and switchboard adds a marker per running bundle under Run/live/ so a
 * unit that is up but whose bundle is mid-removal is never reaped.  The reconcile
 * reaps a Data/<bundle> container only when its bundle is in none of the three.
 * System/ existing is the readiness gate: while it cannot be opened the reconcile
 * reaps nothing.
 */
#define	BSDFILESYSTEM_SYSTEM_DIR	"/Capabilities/System"
#define	BSDFILESYSTEM_APPS_DIR		"/Capabilities/Apps"
#define	BSDFILESYSTEM_RUN_LIVE_DIR	"/Capabilities/Run/live"
#define	BSDFILESYSTEM_RUN_GROUPS_DIR	"/Capabilities/Run/groups"	/* installed-claimed groups */
#define	BSDFILESYSTEM_RECLAIM_POLL	3	/* while still awaiting the first pass */

#define	RETAIN_RIGHTS	ZH_ALL_RIGHTS

/*
 * Obtain the ZFS control device for a BORN-IN-CAPABILITY-MODE broker: openat("zfs")
 * under the switchboard-delivered /dev directory descriptor, never a global path.
 * The module is preloaded at boot (loader.conf zfs_load="YES"), so there is no
 * in-daemon kldload; the capability pool is the boot pool, already imported by
 * the loader (vfs.root.mountfrom), so there is no `zpool import` (which a capmode
 * process cannot spawn anyway).  A pool that is NOT pre-imported cannot be brought
 * up here -- the caller then serves isolated-open only, as with any absent pool.
 * Returns the borrowed /dev/zfs fd, or -1.
 */
int
bsdfilesystem_ensure_zfs(int dev_dirfd)
{
	int zfs_fd;

	if (dev_dirfd < 0) {
		errno = ENXIO;
		return (-1);
	}
	zfs_fd = openat(dev_dirfd, "zfs", O_RDWR | O_CLOEXEC);
	if (zfs_fd == -1) {
		syslog(LOG_WARNING, "openat /dev/zfs: %m");
		return (-1);
	}
	return (zfs_fd);
}

/*
 * A missing configured pool is normal on read-only installer media: ZFS is
 * loaded there, but the target pool does not exist until bsdinstall creates
 * it.  Keep that narrow case out of the boot error stream.  Missing pools on
 * installed systems, and every other provisioning error, remain warnings.
 */
static bool
pool_missing_expected(const char *fstype, uint64_t flags, int error)
{

	return (error == ENOENT && (flags & MNT_RDONLY) != 0 &&
	    strcmp(fstype, "cd9660") == 0);
}

bool
bsdfilesystem_pool_missing_expected(int error)
{
	struct statfs fs;

	if (statfs("/", &fs) == -1)
		return (false);
	return (pool_missing_expected(fs.f_fstypename, fs.f_flags, error));
}

#ifdef BSDFILESYSTEM_TESTING
bool
bsdfilesystem_test_pool_missing_expected(const char *fstype, uint64_t flags, int error)
{

	return (pool_missing_expected(fstype, flags, error));
}
#endif

/*
 * Return the portion of child that lies strictly under parent ("pool/a/b"
 * under "pool" -> "a/b"), or NULL if child is not a proper descendant.
 */
static const char *
rel_under(const char *parent, const char *child)
{
	size_t plen = strlen(parent);

	if (strncmp(child, parent, plen) != 0 || child[plen] != '/')
		return (NULL);
	return (child + plen + 1);
}

/*
 * Ensure every component of relpath exists under root_fd (whose dataset is
 * root_name), creating what is missing, and return an open handle on the leaf
 * with the given rights.  Intermediate handles are closed.
 */
int
bsdfilesystem_ensure_path(int root_fd, const char *relpath, uint64_t rights)
{
	char comp[BSDFILESYSTEM_MAXPATH];
	const char *p = relpath, *slash;
	int cur = -1, next;

	/* Walk one component at a time from root_fd. */
	for (;;) {
		size_t n;

		slash = strchr(p, '/');
		n = slash != NULL ? (size_t)(slash - p) : strlen(p);
		if (n == 0 || n >= sizeof(comp)) {
			if (cur != -1)
				(void)close(cur);
			errno = EINVAL;
			return (-1);
		}
		memcpy(comp, p, n);
		comp[n] = '\0';

		/* Try to open the child; create it if absent. */
		next = tzfs_openat(cur == -1 ? root_fd : cur, comp,
		    slash != NULL ? RETAIN_RIGHTS : rights, ZHF_SUBTREE);
		if (next == -1) {
			if (errno != ENOENT) {
				int e = errno;
				if (cur != -1)
					(void)close(cur);
				errno = e;
				return (-1);
			}
			next = tzfs_create(cur == -1 ? root_fd : cur, comp,
			    ZHF_SUBTREE);
			if (next == -1) {
				int e = errno;
				if (cur != -1)
					(void)close(cur);
				errno = e;
				return (-1);
			}
		}
		if (cur != -1)
			(void)close(cur);
		cur = next;
		if (slash == NULL)
			break;
		p = slash + 1;
	}
	return (cur);
}

static int
path_deepest_first(const void *ap, const void *bp)
{
	const char *a = *(const char * const *)ap;
	const char *b = *(const char * const *)bp;
	size_t alen = strlen(a), blen = strlen(b);

	if (alen < blen)
		return (1);
	if (alen > blen)
		return (-1);
	return (strcmp(b, a));
}

/*
 * Destroy every snapshot of the dataset behind `target` (a full-rights
 * handle).  The kernel lists snapshots by full name ("pool/a/b@snap"); the
 * per-handle destroy verb takes the bare snapshot name after the '@'.
 * Returns 0 when none remain, -1 with errno (EBUSY for a cloned snapshot)
 * on the first failure.
 */
int
bsdfilesystem_destroy_snapshots(int target)
{
	void *buf;
	char **names;
	const char *at;
	size_t len, nnames, i;
	int saved;

	if (tzfs_list_snapshots(target, &buf, &len) == -1)
		return (-1);
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		saved = errno;
		free(buf);
		errno = saved;
		return (-1);
	}
	free(buf);
	saved = 0;
	for (i = 0; i < nnames; i++) {
		at = strchr(names[i], '@');
		if (at == NULL || at[1] == '\0') {
			saved = EPROTO;
			break;
		}
		if (tzfs_snap_destroy(target, at + 1) == -1 &&
		    errno != ENOENT) {
			saved = errno;
			logcmp_log(LOG_WARNING, "reclaim: destroy snapshot %s: %m%s",
			    names[i], saved == EEXIST ?
			    " (a clone depends on it)" : "");
			break;
		}
		BSDFILESYSTEM_PROBE_RECLAIM_SNAPSHOT(names[i]);
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	if (saved != 0) {
		errno = saved;
		return (-1);
	}
	return (0);
}

/* Number of direct child datasets of `fd`; -1 with errno on failure. */
int
bsdfilesystem_count_children(int fd)
{
	void *buf;
	char **names;
	size_t len, nnames;

	if (tzfs_list_children(fd, &buf, &len) == -1)
		return (-1);
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		int saved = errno;

		free(buf);
		errno = saved;
		return (-1);
	}
	free(buf);
	bsdfilesystem_nvl_names_free(names, nnames);
	return ((int)nnames);
}

/* Number of snapshots of the dataset `fd`; -1 with errno on failure. */
int
bsdfilesystem_count_snapshots(int fd)
{
	void *buf;
	char **names;
	size_t len, nnames;

	if (tzfs_list_snapshots(fd, &buf, &len) == -1)
		return (-1);
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		int saved = errno;

		free(buf);
		errno = saved;
		return (-1);
	}
	free(buf);
	bsdfilesystem_nvl_names_free(names, nnames);
	return ((int)nnames);
}

/* Destroy one capability-owned subtree, deepest datasets first. */
static int	destroy_tree_r(int parent_fd, const char *relname, int depth);

int
bsdfilesystem_destroy_tree(int parent_fd, const char *relname)
{

	return (destroy_tree_r(parent_fd, relname, 0));
}

static int
destroy_tree_r(int parent_fd, const char *relname, int depth)
{
	struct zfd_info_args info;
	void *buf;
	char **children, **names;
	const char *name, *rel;
	size_t len, prefix_len, count, nnames, i;
	int target, saved;

	if (relname == NULL || relname[0] == '\0' || strchr(relname, '/') != NULL) {
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Bound the recursion: a caller can nest child datasets arbitrarily
	 * deep under a subtree claim, and an unbounded recursive destroy would
	 * overflow the stack (a crash in the privileged reaper stops all
	 * reclaim).  Fail rather than recurse past the bound; the deep remnant
	 * is left (a bounded self-inflicted leak) but nothing crashes.
	 */
	if (depth >= BSDFILESYSTEM_DESTROY_MAX_DEPTH) {
		errno = ELOOP;
		return (-1);
	}
	target = tzfs_openat(parent_fd, relname, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	if (target == -1)
		return (errno == ENOENT ? 0 : -1);
	memset(&info, 0, sizeof(info));
	if (tzfs_info(target, &info) == -1 ||
	    tzfs_list_children(target, &buf, &len) == -1) {
		saved = errno;
		close(target);
		errno = saved;
		return (-1);
	}
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		saved = errno;
		free(buf);
		close(target);
		errno = saved;
		return (-1);
	}
	free(buf);
	prefix_len = strlen(info.zi_name);
	count = 0;
	children = calloc(nnames == 0 ? 1 : nnames, sizeof(*children));
	if (children == NULL) {
		bsdfilesystem_nvl_names_free(names, nnames);
		close(target);
		return (-1);
	}
	for (i = 0; i < nnames; i++) {
		name = names[i];
		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/') {
			saved = EPROTO;
			goto out;
		}
		rel = name + prefix_len + 1;
		children[count] = strdup(rel);
		if (children[count] == NULL) {
			saved = errno;
			goto out;
		}
		count++;
	}
	/*
	 * tzfs_list_children returns only the direct children of target (the
	 * kernel's dmu_dir_list_next walks one directory level, not the whole
	 * subtree), and tzfs_destroy refuses a dataset that still has children.
	 * Recurse into each direct child so its own descendants are destroyed
	 * bottom-up first; a real container is Data/<bundle>/<unit>/persistent/
	 * <claim> -- four levels below the bundle -- so a flat one-level destroy
	 * would fail on the non-empty <unit> and leave the container un-reaped.
	 */
	qsort(children, count, sizeof(*children), path_deepest_first);
	for (i = 0; i < count; i++) {
		if (destroy_tree_r(target, children[i], depth + 1) == -1) {
			saved = errno;
			goto out;
		}
	}
	/*
	 * Snapshots belong to the container being reaped: ZFS refuses to
	 * destroy a dataset that still has them (EBUSY), so drop them first,
	 * as "zfs destroy -r" would.  A snapshot pinned by a clone that lives
	 * OUTSIDE the container (an operator's backup clone) cannot be dropped
	 * (ZFS reports a branch point as EEXIST); that reap fails, is counted
	 * as failed, and is retried on every later pass until the clone is
	 * gone -- never destroyed from under it.
	 */
	if (bsdfilesystem_destroy_snapshots(target) == -1) {	/* EEXIST: cloned */
		saved = errno;
		goto out;
	}
	close(target);
	target = -1;
	if (tzfs_destroy(parent_fd, relname) == -1 && errno != ENOENT) {
		saved = errno;
		goto out;
	}
	saved = 0;
out:
	for (i = 0; i < count; i++)
		free(children[i]);
	free(children);
	bsdfilesystem_nvl_names_free(names, nnames);
	if (target != -1)
		close(target);
	if (saved != 0) {
		errno = saved;
		return (-1);
	}
	return (0);
}

static int
reconcile_boot_generations(struct bsdfilesystem_state *st)
{
	struct timeval boottime;
	struct zfd_info_args info;
	void *buf;
	char **names;
	const char *name, *rel;
	size_t len, prefix_len, sz, nnames, i;

	sz = sizeof(boottime);
	if (sysctlbyname("kern.boottime", &boottime, &sz, NULL, 0) == -1)
		return (-1);
	(void)snprintf(st->boot_name, sizeof(st->boot_name),
	    "boot-%016jx-%08lx", (uintmax_t)boottime.tv_sec,
	    (unsigned long)boottime.tv_usec);
	memset(&info, 0, sizeof(info));
	if (tzfs_info(st->ephemeral_fd, &info) == -1 ||
	    tzfs_list_children(st->ephemeral_fd, &buf, &len) == -1)
		return (-1);
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		free(buf);
		return (-1);
	}
	free(buf);
	prefix_len = strlen(info.zi_name);
	for (i = 0; i < nnames; i++) {
		name = names[i];
		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/')
			continue;
		rel = name + prefix_len + 1;
		if (strchr(rel, '/') == NULL && strncmp(rel, "boot-", 5) == 0 &&
		    strcmp(rel, st->boot_name) != 0 &&
		    bsdfilesystem_destroy_tree(st->ephemeral_fd, rel) == -1) {
			logcmp_log(LOG_WARNING, "reconcile stale boot storage %s: %m",
			    rel);
		}
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	st->boot_fd = bsdfilesystem_ensure_path(st->ephemeral_fd, st->boot_name,
	    RETAIN_RIGHTS);
	return (st->boot_fd == -1 ? -1 : 0);
}

/*
 * Reap orphaned ephemeral leases.  A lease (ephemeral/lease-<session>) is bound
 * to the lifetime of the connection that began it.  Called once at daemon
 * startup, before any connection is served: no lease has a live owner yet, so
 * every lease-* under ephemeral is an orphan left by a prior boot and is
 * destroyed.  This is the boot-scoped GC that bsdfilesystem_session_begin used to do by
 * reaping "every lease but mine" — which is unsafe once concurrent connections
 * each own their own lease, so it lives here instead.
 */
int
bsdfilesystem_reap_leases(struct bsdfilesystem_state *st)
{
	struct zfd_info_args info;
	void *buf;
	char **names;
	const char *name, *rel;
	size_t len, prefix_len, nnames, i;
	int rc = 0;

	memset(&info, 0, sizeof(info));
	if (tzfs_info(st->ephemeral_fd, &info) == -1 ||
	    tzfs_list_children(st->ephemeral_fd, &buf, &len) == -1)
		return (-1);
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		free(buf);
		return (-1);
	}
	free(buf);
	prefix_len = strlen(info.zi_name);
	for (i = 0; i < nnames; i++) {
		name = names[i];
		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/')
			continue;
		rel = name + prefix_len + 1;
		if (strchr(rel, '/') == NULL && strncmp(rel, "lease-", 6) == 0 &&
		    bsdfilesystem_destroy_tree(st->ephemeral_fd, rel) == -1) {
			rc = -1;
			break;
		}
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	return (rc);
}

/*
 * A TXN staging clone (and the del-<id> transient a mid-swap commit leaves) is
 * named with the unpredictable `v<hex>` version-id shape gen_version_id() mints:
 * a leading 'v' followed by >=16 lowercase hex digits (nanosecond clock + pid +
 * counter).  A caller-chosen claim name never takes this shape, so the sweep
 * below can require it before trusting the txnbase property -- fail-safe against
 * ever reaping a real claim (which, once committed, still carries the inherited
 * property until TXN_COMMIT clears it).
 */
bool
bsdfilesystem_is_version_id_name(const char *s)
{
	size_t i;

	if (s[0] != 'v')
		return (false);
	for (i = 1; s[i] != '\0'; i++)
		if (!isxdigit((unsigned char)s[i]))
			return (false);
	return (i >= 17);	/* 'v' + at least 16 hex digits */
}

/*
 * A version-id name embeds its creation instant: the 16 hex digits after the
 * leading 'v' are (tv_sec*1e9 + tv_nsec) at gen_version_id() time.  Return true
 * iff that instant is at least `grace` seconds in the past.  Used by the idle
 * staging reap to leave a just-created clone alone during the sub-second window
 * between TXN_BEGIN's clone and its mount (when a concurrent reconcile could
 * otherwise race it); a clone created in the future (clock skew) counts as fresh.
 * Caller guarantees is_version_id_name(rel), so rel[1..16] are hex.
 */
static bool
staging_older_than(const char *rel, time_t grace)
{
	char nsbuf[17];
	unsigned long long ns;
	struct timespec now;

	memcpy(nsbuf, rel + 1, 16);
	nsbuf[16] = '\0';
	errno = 0;
	ns = strtoull(nsbuf, NULL, 16);
	if (errno != 0 || clock_gettime(CLOCK_REALTIME, &now) == -1)
		return (false);		/* unparseable/no clock: never age-reap */
	return ((time_t)(ns / 1000000000ull) + grace <= now.tv_sec);
}

/*
 * Recursively walk one persistent-tree directory, destroying orphaned TXN
 * staging clones beneath it.  A clone is a candidate iff it is a reserved
 * del-<id> transient, OR it carries the BSDFILESYSTEM_TXN_BASE_PROP stamp AND has
 * the version-id name shape (both required: a committed claim keeps the inherited
 * property for one commit if the clear raced, but never the version-id name).
 *
 * `grace` selects the caller:
 *   0  = the boot sweep -- every candidate is an orphan (nothing survives a
 *        reboot), reaped unconditionally.
 *   >0 = the idle reap running in the reconcile loop while units are live --
 *        only a STAMPED clone older than `grace` seconds is reaped, and a
 *        del-<id> transient is left to the boot sweep.  Correctness rests on
 *        ZFS: a clone held by a live transaction is MOUNTED (TXN_BEGIN mounts
 *        it and the connection's anchor holds it), and a mounted dataset cannot
 *        be destroyed -- tzfs_destroy fails EBUSY, which is expected here and
 *        left quietly for a later pass.  An abandoned clone was UNMOUNTED by its
 *        connection's teardown, so it destroys cleanly.  The age grace only
 *        avoids racing an in-progress TXN_BEGIN.
 *
 * Every other child is an ordinary claim or namespace directory and is descended
 * into.  Best-effort: a failed reap is logged and counted, never fatal.
 */
static int
reap_staging_walk(int dir_fd, int depth, time_t grace)
{
	struct zfd_info_args info;
	void *buf;
	char **names;
	const char *name, *rel;
	size_t len, prefix_len, nnames, i;
	int rc = 0;

	if (depth > BSDFILESYSTEM_STAGING_WALK_MAX)
		return (0);
	memset(&info, 0, sizeof(info));
	if (tzfs_info(dir_fd, &info) == -1 ||
	    tzfs_list_children(dir_fd, &buf, &len) == -1)
		return (-1);
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		free(buf);
		return (-1);
	}
	free(buf);
	prefix_len = strlen(info.zi_name);
	for (i = 0; i < nnames; i++) {
		char base[BSDFILESYSTEM_NAME_MAX];
		uint64_t iv = 0;
		uint32_t src = 0;
		int is_str = 0, child;
		bool orphan, from_prop = false;

		name = names[i];
		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/')
			continue;
		rel = name + prefix_len + 1;
		if (strchr(rel, '/') != NULL)
			continue;	/* only direct children */
		base[0] = '\0';
		/*
		 * A del-<id> transient is an orphan -- but only the boot sweep
		 * (grace == 0) reaps it; the idle reap leaves it, since it has no
		 * txnbase stamp to age-check and is a rare mid-swap-crash remnant.
		 */
		orphan = grace == 0 && strncmp(rel, BSDFILESYSTEM_STAGING_PREFIX,
		    sizeof(BSDFILESYSTEM_STAGING_PREFIX) - 1) == 0;
		child = tzfs_openat(dir_fd, rel, ZH_ALL_RIGHTS, ZHF_SUBTREE);
		if (child == -1)
			continue;	/* raced away; nothing to reap */
		if (!orphan && bsdfilesystem_is_version_id_name(rel)) {
			/*
			 * Read the txnbase stamp: it names the base claim (so the
			 * base snapshot can be dropped) and, for the idle reap,
			 * gates the reap.  The BOOT sweep reaps ANY v<hex>-named
			 * dataset regardless of the stamp -- a real claim can never
			 * take that shape (valid_dataset reserves it), so a v<hex>
			 * name at boot is always a staging clone, including one a
			 * commit cleared the stamp on and then crashed before
			 * finishing the swap.  The IDLE reap still requires the
			 * stamp AND the age grace, so it never touches a live
			 * commit's clone (whose stamp is cleared for the swap).
			 */
			if (tzfs_get_one_prop(child, BSDFILESYSTEM_TXN_BASE_PROP,
			    base, sizeof(base), &iv, &is_str, &src) == 0 &&
			    is_str && base[0] != '\0')
				from_prop = true;	/* base claim name known */
			if (grace == 0)
				orphan = true;
			else if (from_prop && staging_older_than(rel, grace))
				orphan = true;
		}
		if (orphan) {
			(void)close(child);
			if (bsdfilesystem_destroy_tree(dir_fd, rel) == -1) {
				/*
				 * EBUSY in idle mode means the clone is still
				 * mounted by a live transaction: expected, not a
				 * failure -- leave it for a later pass.
				 */
				if (grace != 0 && errno == EBUSY)
					continue;
				logcmp_log(LOG_WARNING,
				    "reclaim: destroy abandoned txn staging %s: %m",
				    rel);
				rc = -1;
			} else {
				/*
				 * Drop the base snapshot <base>@<rel> the clone
				 * was made from, exactly as TXN_ABORT does: with
				 * the clone gone it is unreferenced, and left
				 * behind it pins space and surfaces in
				 * LIST_VERSIONS as a phantom version the caller
				 * never took.  The base claim name is the txnbase
				 * stamp; only the property path knows it (a del-
				 * transient's origin snapshot was already migrated
				 * onto the live claim by the promote).  Best-effort.
				 */
				if (from_prop) {
					int cfd = tzfs_openat(dir_fd, base,
					    ZH_SNAP_DESTROY, ZHF_SUBTREE);
					if (cfd != -1) {
						(void)tzfs_snap_destroy(cfd, rel);
						(void)close(cfd);
					}
				}
				logcmp_log(LOG_NOTICE,
				    "reclaim: destroyed abandoned txn staging %s",
				    rel);
			}
			continue;
		}
		/* An ordinary claim/namespace dir: descend to reach its clones. */
		if (reap_staging_walk(child, depth + 1, grace) == -1)
			rc = -1;
		(void)close(child);
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	return (rc);
}

/*
 * Boot-scoped GC of orphaned TXN staging clones in the persistent tree.  A
 * TXN_BEGIN stages a read-write clone of a claim as a sibling in the caller's
 * namespace, and it is reaped explicitly by TXN_COMMIT/TXN_ABORT.  A caller that
 * begins a transaction and then vanishes without committing or aborting leaves
 * that clone behind: it is deliberately NOT tagged ephemeral (a transaction may
 * legitimately span connections so it can be resumed), so connection teardown
 * only unmounts it; it lives in the persistent tree, so the ephemeral lease and
 * boot-generation GC never see it; and the container reconcile only reaps whole
 * uninstalled bundles -- so nothing reclaims it while its bundle stays installed.
 * A transaction cannot span a reboot (its connection is gone), so at daemon
 * startup EVERY staging clone is such an orphan.  Runs once here, before any
 * connection is served, so it never races a live transaction.  Non-fatal.
 */
int
bsdfilesystem_reap_staging(struct bsdfilesystem_state *st)
{

	return (reap_staging_walk(st->persistent_fd, 0, 0));
}

/*
 * Idle reap of abandoned TXN staging clones while units are live, run each
 * settled reconcile pass.  The boot sweep above only reclaims at startup, so on
 * a long-uptime system an abandoned clone (client began a txn and vanished)
 * would otherwise pin space until the next reboot.  This closes that gap: it
 * reaps only a stamped clone older than BSDFILESYSTEM_STAGING_IDLE_GRACE, and a
 * clone held by a LIVE transaction is protected by ZFS itself -- it is still
 * mounted, so its destroy fails EBUSY and is left for a later pass (see
 * reap_staging_walk).  Non-fatal.
 */
int
bsdfilesystem_reap_idle_staging(struct bsdfilesystem_state *st)
{

	return (reap_staging_walk(st->persistent_fd, 0,
	    (time_t)st->cfg.staging_idle_grace));
}

/*
 * Begin (create or open) this connection's ephemeral lease.  Each live
 * connection owns exactly one lease-<session> and this NEVER reaps another
 * connection's lease: concurrent consumers must not delete one another's
 * storage.  Leases orphaned across a reboot are cleared by bsdfilesystem_reap_leases()
 * at startup.
 */
int
bsdfilesystem_session_begin(struct bsdfilesystem_state *st, const char *session)
{
	const char *p;
	char wanted[BSDFILESYSTEM_NAME_MAX];

	if (session == NULL || strlen(session) != BSDFILESYSTEM_SESSION_MAX - 1) {
		errno = EINVAL;
		return (-1);
	}
	for (p = session; *p != '\0'; p++)
		if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
			errno = EINVAL;
			return (-1);
		}
	(void)snprintf(wanted, sizeof(wanted), "lease-%s", session);
	if (st->lease_fd != -1)
		close(st->lease_fd);
	st->lease_fd = bsdfilesystem_ensure_path(st->ephemeral_fd, wanted,
	    RETAIN_RIGHTS);
	if (st->lease_fd == -1)
		return (-1);
	strlcpy(st->lease_name, wanted, sizeof(st->lease_name));
	return (0);
}

/*
 * libcapreclaim enumerate callback: emit every per-bundle container bsdfilesystem holds,
 * by its top-level bundle name.  Durable data lives at Data/<bundle>/<unit>/...,
 * so the direct children of the Data root are the bundle names -- exactly the
 * key the reconcile compares against the installed bundle set (System/, Apps/).
 * Mirrors bsdfilesystem_reap_leases: list the children of the retained Data parent and
 * keep only the single top-level component (a nested unit/persistent dataset is
 * not itself a container).
 */
static int
persistent_enumerate(void *arg,
    void (*emit)(void *emit_arg, const char *owner), void *emit_arg)
{
	struct bsdfilesystem_state *st = arg;
	struct zfd_info_args info;
	void *buf;
	char **names;
	const char *name, *rel;
	size_t len, prefix_len, nnames, i;

	if (st->persistent_fd == -1)
		return (0);			/* no pool: nothing owned */
	memset(&info, 0, sizeof(info));
	if (tzfs_info(st->persistent_fd, &info) == -1 ||
	    tzfs_list_children(st->persistent_fd, &buf, &len) == -1)
		return (-1);
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		free(buf);
		return (-1);
	}
	free(buf);
	prefix_len = strlen(info.zi_name);
	for (i = 0; i < nnames; i++) {
		name = names[i];
		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/')
			continue;
		rel = name + prefix_len + 1;
		if (strcmp(rel, BSDFILESYSTEM_SHARED_DIR) == 0)
			continue;	/* group containers: reaped by membership */
		if (strchr(rel, '/') == NULL)
			emit(emit_arg, rel);
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	return (0);
}

/*
 * libcapreclaim destroy callback: reap one gone owner's entire persistent
 * namespace, deepest dataset first, exactly as OP_DESTROY/reclaim do.  The
 * owner key is a single '/'-free component, and bsdfilesystem_destroy_tree refuses any
 * relname bearing a '/', so this can only ever touch derive_ns(owner)'s subtree.
 */
static int
persistent_destroy(void *arg, const char *owner)
{
	struct bsdfilesystem_state *st = arg;
	int rc;

	rc = bsdfilesystem_destroy_tree(st->persistent_fd, owner);
	BSDFILESYSTEM_PROBE_RECLAIM_DESTROY(owner, rc == 0 ? 0 : errno);
	if (rc == 0)
		syslog(LOG_NOTICE,
		    "reclaim: destroyed orphan persistent namespace %s", owner);
	else
		syslog(LOG_WARNING,
		    "reclaim: destroy orphan persistent namespace %s: %m%s",
		    owner, errno == EBUSY || errno == EEXIST ? " (mounted, or "
		    "a snapshot is pinned by a clone outside the container; "
		    "retried next pass)" : "");
	return (rc);
}

/*
 * Group containers (Data/Shared/<group>/) are reaped BY MEMBERSHIP: one is an
 * orphan only when no installed bundle still declares the group.  Switchboard
 * publishes the installed-claimed groups as Run/groups/<group> markers (from
 * every installed bundle's Bundle.ucl `groups`), the delivered view this
 * reconcile compares against.  Enumerate = the children of Data/Shared.
 */
static int
groups_enumerate(void *arg,
    void (*emit)(void *emit_arg, const char *owner), void *emit_arg)
{
	struct bsdfilesystem_state *st = arg;
	struct zfd_info_args info;
	void *buf;
	char **names;
	size_t len, nnames, prefix_len, i;
	int shared_fd, saved;

	if (st->persistent_fd == -1)
		return (0);
	shared_fd = tzfs_openat(st->persistent_fd, BSDFILESYSTEM_SHARED_DIR,
	    ZH_ALL_RIGHTS, ZHF_SUBTREE);
	if (shared_fd == -1)
		return (errno == ENOENT ? 0 : -1);	/* no groups yet */
	memset(&info, 0, sizeof(info));
	if (tzfs_info(shared_fd, &info) == -1 ||
	    tzfs_list_children(shared_fd, &buf, &len) == -1) {
		saved = errno;
		close(shared_fd);
		errno = saved;
		return (-1);
	}
	close(shared_fd);
	if (bsdfilesystem_nvl_names(buf, len, &names, &nnames) == -1) {
		saved = errno;
		free(buf);
		errno = saved;
		return (-1);
	}
	free(buf);
	prefix_len = strlen(info.zi_name);
	for (i = 0; i < nnames; i++) {
		const char *name = names[i];

		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/' ||
		    strchr(name + prefix_len + 1, '/') != NULL)
			continue;
		emit(emit_arg, name + prefix_len + 1);
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	return (0);
}

static int
groups_destroy(void *arg, const char *group)
{
	struct bsdfilesystem_state *st = arg;
	int shared_fd, rc, saved;

	shared_fd = tzfs_openat(st->persistent_fd, BSDFILESYSTEM_SHARED_DIR,
	    ZH_ALL_RIGHTS, ZHF_SUBTREE);
	if (shared_fd == -1)
		return (errno == ENOENT ? 0 : -1);
	rc = bsdfilesystem_destroy_tree(shared_fd, group);
	saved = errno;
	close(shared_fd);
	BSDFILESYSTEM_PROBE_RECLAIM_DESTROY(group, rc == 0 ? 0 : saved);
	if (rc == 0)
		syslog(LOG_NOTICE,
		    "reclaim: destroyed orphan group container Shared/%s", group);
	else
		syslog(LOG_WARNING,
		    "reclaim: destroy orphan group container Shared/%s: %s",
		    group, strerror(saved));
	errno = saved;
	return (rc);
}

/*
 * The reconcile loop: the container-model cleanup for persistent state.  Runs
 * in a forked child so it never blocks the serve loop, and stays out of
 * capability mode so it can re-open the live directory by path each pass (it is
 * a privileged reaper; it never accepts client input).  It compares the owners
 * it holds against switchboard's published live set and destroys the orphans --
 * immediately on the first authoritative pass (BOOT: the state is settled), and
 * only "seen gone twice" thereafter (TIMER: the interval is the grace window,
 * so an upgrade's transient absence is never confirmed).  It NEVER reaps unless
 * the install root (System/) is present, so a missing or unreadable live set is
 * fail-safe.
 */
static void __dead2
bsdfilesystem_reaper_loop(struct bsdfilesystem_state *st)
{
	struct capreclaim r = CAPRECLAIM_INIT, g = CAPRECLAIM_INIT;
	struct capreclaim_stats stats, gstats;
	enum capreclaim_when when = CAPRECLAIM_BOOT, gwhen = CAPRECLAIM_BOOT;
	unsigned nap, gpolls = 0;

	setproctitle("-Filesystem[reclaim]");
	r.enumerate = persistent_enumerate;
	r.destroy = persistent_destroy;
	r.arg = st;
	r.stats = &stats;
	r.status_dirfd = capreclaim_status_dir();	/* -1 if unavailable: no record */
	r.status_name = "Filesystem";
	g.enumerate = groups_enumerate;
	g.destroy = groups_destroy;
	g.arg = st;
	g.stats = &gstats;
	g.status_dirfd = r.status_dirfd;
	g.status_name = "Filesystem-groups";
	/*
	 * Run/groups existing is this reconcile's readiness gate (switchboard
	 * creates it before launching anything), so an EMPTY marker set is a
	 * genuine "no installed bundle claims any group" and the last group
	 * container must reap -- opt out of the library's empty-set floor.
	 */
	g.allow_empty_live = true;

	for (;;) {
		int sys_fd, apps_fd, run_fd;

		/*
		 * System/ is the authoritative install root; its presence is the
		 * readiness gate.  While it cannot be opened (an installer image with
		 * no plane, say) the reconcile reaps nothing.
		 */
		/*
		 * Born in capability mode: reopen the install directories from the
		 * retained, switchboard-delivered root fd (openat with a relative
		 * path), never by absolute path.  A fresh openat each pass yields a
		 * dir handle at offset 0 reflecting the current install state.
		 * root_fd < 0 (no delivered root) => no reconcile source.
		 */
		sys_fd = st->root_fd >= 0 ? openat(st->root_fd,
		    "Capabilities/System", O_DIRECTORY | O_RDONLY | O_CLOEXEC) : -1;
		if (sys_fd != -1) {
			int n;

			apps_fd = openat(st->root_fd, "Capabilities/Apps",
			    O_DIRECTORY | O_RDONLY | O_CLOEXEC);
			run_fd = openat(st->root_fd, "Capabilities/Run/live",
			    O_DIRECTORY | O_RDONLY | O_CLOEXEC);
			r.sources[0].fd = sys_fd;
			r.sources[0].strip_cap = true;	/* System/<Bundle>.cap */
			r.sources[1].fd = apps_fd;	/* -1 if absent: skipped */
			r.sources[1].strip_cap = true;	/* Apps/<Bundle>.cap */
			r.sources[2].fd = run_fd;	/* -1 if absent: skipped */
			r.sources[2].strip_cap = false;	/* Run/live/<bundle> */
			r.nsources = 3;
			n = capreclaim_run(&r, when);
			BSDFILESYSTEM_PROBE_RECLAIM_PASS((int)when, stats.nlive,
			    stats.nowned, stats.norphans, stats.ndestroyed,
			    stats.nfailed);
			if (n == -1)
				logcmp_log(LOG_WARNING, "reclaim: %s pass failed: %m",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer");
			else if (n > 0 || stats.nfailed > 0)
				syslog(LOG_NOTICE,
				    "reclaim: %s pass reaped %d orphan%s (%u live, "
				    "%u owned, %u orphaned, %u failed)",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer",
				    n, n == 1 ? "" : "s", stats.nlive, stats.nowned,
				    stats.norphans, stats.nfailed);
			/* A floored pass saw nothing: the boot pass is still owed. */
			if (n >= 0 && !stats.floored)
				when = CAPRECLAIM_TIMER;
			if (apps_fd != -1)
				(void)close(apps_fd);
			if (run_fd != -1)
				(void)close(run_fd);
			(void)close(sys_fd);
		}
		/*
		 * Group containers reconcile against switchboard's installed-
		 * claimed group markers; that directory existing is their own
		 * readiness gate (switchboard publishes it before launching any
		 * unit), so a pass before it appears reaps nothing and does not
		 * consume the boot pass.
		 */
		{
			int groups_fd = st->root_fd >= 0 ? openat(st->root_fd,
			    "Capabilities/Run/groups",
			    O_DIRECTORY | O_RDONLY | O_CLOEXEC) : -1;

			if (groups_fd != -1) {
				int n;

				g.sources[0].fd = groups_fd;
				g.sources[0].strip_cap = false;
				g.nsources = 1;
				n = capreclaim_run(&g, gwhen);
				BSDFILESYSTEM_PROBE_RECLAIM_PASS((int)gwhen + 2, gstats.nlive,
				    gstats.nowned, gstats.norphans, gstats.ndestroyed,
				    gstats.nfailed);
				if (n == -1)
					syslog(LOG_WARNING,
					    "reclaim: group %s pass failed: %m",
					    gwhen == CAPRECLAIM_BOOT ? "boot" : "timer");
				else if (n > 0 || gstats.nfailed > 0)
					syslog(LOG_NOTICE,
					    "reclaim: group %s pass reaped %d container%s "
					    "(%u live, %u owned, %u orphaned, %u failed)",
					    gwhen == CAPRECLAIM_BOOT ? "boot" : "timer",
					    n, n == 1 ? "" : "s", gstats.nlive,
					    gstats.nowned, gstats.norphans, gstats.nfailed);
				if (n >= 0 && !gstats.floored)
					gwhen = CAPRECLAIM_TIMER;
				(void)close(groups_fd);
			}
		}
		/*
		 * Idle reap of abandoned TXN staging clones (a client that began a
		 * transaction and vanished).  Only once the container reconcile has
		 * settled onto the timer cadence -- during the startup poll burst the
		 * boot sweep has already run and units may still be establishing txns.
		 * A live txn's clone is mounted and so survives (EBUSY); only stamped
		 * clones older than the grace are reclaimed.
		 */
		if (when == CAPRECLAIM_TIMER &&
		    bsdfilesystem_reap_idle_staging(st) == -1)
			logcmp_log(LOG_WARNING, "reclaim: idle staging reap: %m");
		/*
		 * Poll briefly until the first settled pass, then sleep the full
		 * grace interval between timer passes.
		 */
		/*
		 * Poll briefly while EITHER reconcile still awaits its settled boot
		 * pass: the group view (Run/groups) appears only once switchboard
		 * has started, later than System/.  Bound the group wait so a plane
		 * that never publishes it (installer media) falls back to the timer.
		 */
		nap = (when == CAPRECLAIM_BOOT ||
		    (gwhen == CAPRECLAIM_BOOT && gpolls++ < 60)) ? BSDFILESYSTEM_RECLAIM_POLL :
		    st->cfg.reclaim_interval;
		(void)sleep(nap);
	}
}

/*
 * Fork the per-bundle container reconcile child.  Called at boot after the
 * ephemeral-lease reap and before the provider enters capability mode, so the
 * child inherits the retained Data-root handle and can read the install
 * directories by path.  Non-fatal: a fork failure just means cleanup is
 * deferred, never a boot failure (no hard dependency on the reaper).
 */
void
bsdfilesystem_start_reaper(struct bsdfilesystem_state *st)
{
	pid_t pid;

	if (st->persistent_fd == -1)
		return;				/* no persistent state to reap */
	pid = fork();
	if (pid == -1) {
		logcmp_log(LOG_WARNING, "reclaim: fork: %m");
		return;
	}
	if (pid == 0) {
		(void)signal(SIGCHLD, SIG_DFL);
		bsdfilesystem_reaper_loop(st);
		/* NOTREACHED */
	}
}

int
bsdfilesystem_layout_provision(struct bsdfilesystem_state *st)
{
	struct bsdfilesystem_config *cfg = &st->cfg;
	const char *rel;
	int zpd, root_fd;

	/*
	 * Pool root handle: the anchor for the whole /Capabilities tree.  The
	 * pool handle must hold at least the rights we then derive for the root
	 * dataset handle (pool_root_open requires a subset), so open it with the
	 * full mask; bsdfilesystem runs as root and owns the storage plane.
	 */
	zpd = tzfs_pool_open_fd(st->zfs_fd, cfg->pool, RETAIN_RIGHTS);
	if (zpd == -1)
		return (-1);
	root_fd = tzfs_pool_root_open(zpd, RETAIN_RIGHTS, ZHF_SUBTREE);
	(void)close(zpd);
	if (root_fd == -1) {
		syslog(LOG_ERR, "pool_root_open %s: %m", cfg->pool);
		return (-1);
	}

	/*
	 * Make the whole /Capabilities dataset subtree INVISIBLE to OS mount
	 * management.  bsdfilesystem's datasets are reached exclusively through capability
	 * handles and ANONYMOUS mounts (ZFD_MOUNT / ZH_MOUNT: the objset is mounted
	 * without any global-namespace mountpoint and accessed only through the
	 * returned dir fd — see sys/sys/zfshandle.h).  They must therefore never be
	 * mounted by the OS's boot-time `zfs mount -a`.  If the OS mounts one at its
	 * inherited mountpoint, the objset is already mounted, and bsdfilesystem's anonymous
	 * mount (and any destroy) of the SAME dataset fails EBUSY.  That is the
	 * second-boot collision: on a fresh boot the datasets do not exist yet, but
	 * on every reboot the persisted datasets are OS-mounted before switchboard
	 * runs, so a reused persistent claim makes the consumer's storage request
	 * fail EBUSY (a crash-looping bsdlog) and a stale ephemeral generation makes
	 * the reconcile destroy fail EBUSY.
	 *
	 * Setting the base dataset's mountpoint to "none" propagates by inheritance
	 * to every child — persistent, ephemeral, per-service homes and claims,
	 * boot/lease generations — so the OS mounts none of them, and bsdfilesystem owns the
	 * (anonymous) mount lifecycle completely.  It also keeps the static
	 * /Capabilities/System bundle tree visible, since the base is not mounted
	 * over the root dataset's /Capabilities.  canmount=off is kept as belt-and-
	 * suspenders on the base itself (integer-encoded property, so the uint64
	 * setter — the string path panics ZFS on an int property).
	 */
	rel = rel_under(cfg->pool, cfg->base);
	if (rel != NULL) {
		int base_fd = bsdfilesystem_ensure_path(root_fd, rel, RETAIN_RIGHTS);

		if (base_fd == -1) {
			syslog(LOG_ERR, "provision %s: %m", cfg->base);
			(void)close(root_fd);
			return (-1);
		}
		/* mountpoint is a genuine string property; setting it "none" here
		 * propagates to the whole subtree by inheritance. */
		if (tzfs_set_prop_string(base_fd, "mountpoint", "none") == -1)
			syslog(LOG_WARNING, "set mountpoint=none on %s: %m "
			    "(datasets may be OS-mounted and collide after reboot)",
			    cfg->base);
		if (tzfs_set_prop_uint64(base_fd, "canmount", 0) == -1)
			syslog(LOG_WARNING, "set canmount=off on %s: %m", cfg->base);
		(void)close(base_fd);
	}

	/* base/persistent/ephemeral all hang under the pool root. */
	rel = rel_under(cfg->pool, cfg->persistent);
	if (rel == NULL ||
	    (st->persistent_fd = bsdfilesystem_ensure_path(root_fd, rel, RETAIN_RIGHTS)) ==
	    -1) {
		syslog(LOG_ERR, "provision %s: %m", cfg->persistent);
		(void)close(root_fd);
		return (-1);
	}
	rel = rel_under(cfg->pool, cfg->ephemeral);
	if (rel == NULL ||
	    (st->ephemeral_fd = bsdfilesystem_ensure_path(root_fd, rel, RETAIN_RIGHTS)) ==
	    -1) {
		syslog(LOG_ERR, "provision %s: %m", cfg->ephemeral);
		(void)close(root_fd);
		return (-1);
	}
	/*
	 * Apply the configured sync= policy to the ephemeral subtree.  sync is an
	 * index-encoded property (like canmount): STANDARD=0, ALWAYS=1,
	 * DISABLED=2 — set via the uint64 path (the string path panics ZFS on an
	 * integer property).  Setting it on the ephemeral parent propagates by
	 * inheritance to every child (boot/lease generations, per-service homes,
	 * claims).  Best-effort: a sync miss is a durability/perf knob, not a
	 * correctness gate for provisioning.
	 */
	{
		uint64_t syncval;

		if (strcmp(cfg->ephemeral_sync, "standard") == 0)
			syncval = 0;	/* ZFS_SYNC_STANDARD */
		else if (strcmp(cfg->ephemeral_sync, "always") == 0)
			syncval = 1;	/* ZFS_SYNC_ALWAYS */
		else
			syncval = 2;	/* ZFS_SYNC_DISABLED */
		if (tzfs_set_prop_uint64(st->ephemeral_fd, "sync", syncval) == -1)
			syslog(LOG_WARNING, "set sync=%s on %s: %m",
			    cfg->ephemeral_sync, cfg->ephemeral);
	}
	(void)close(root_fd);
	if (reconcile_boot_generations(st) == -1) {
		int e = errno;
		syslog(LOG_ERR, "provision current boot storage: %m");
		errno = e;	/* syslog() may clobber errno; main() reports it */
		return (-1);
	}

	syslog(LOG_INFO, "provisioned %s {persistent,ephemeral}",
	    cfg->base);
	return (0);
}
