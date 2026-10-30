/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdfilesystem(8) layout provisioning beneath a dataset handle. The maintained
 * provider is born in capability mode. BIP requires a bootstrap-delivered base;
 * the non-BIP acquisition path can mint that base from an already imported pool.
 * Neither path imports pools here. Serving retains only bounded child handles.
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
 * Installed bundle directories and running-bundle markers supply observations
 * for reconciliation (docs/book/src/plane/containers-and-storage.md). Absence
 * from this view is not persistent-data deletion authority: retained generations
 * and recovery records may still reference the data. The persistent callbacks
 * retain containers with EBUSY pending an authenticated lifecycle protocol.
 * A missing System/ source prevents bundle reconciliation.
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
	struct zfd_info_args info;
	void *buf;
	char **names;
	const char *name, *rel;
	size_t len, prefix_len, nnames, i;

	if (storage_namespace_boot_name(st->boot_name, sizeof(st->boot_name)) == -1)
		return (-1);
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
 * Sweep ephemeral leases before this daemon instance accepts connections.
 * TODO: daemon startup is not proof of a new boot.  PD_DAEMON workers and
 * delivered mount descriptors may survive a same-boot provider restart.
 * A lease needs verified lifetime ownership before recursive reclamation;
 * a final EBUSY does not undo child or snapshot destruction already performed.
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
	return (storage_namespace_version_name(s));
}

/*
 * Inventory unresolved transaction datasets without mutating them. Neither a
 * reserved name, an old timestamp, nor a txnbase property proves that its owner
 * is gone or publication completed. A mounted parent is also insufficient:
 * recursive deletion can destroy snapshots/children before returning EBUSY.
 * Reclamation requires an authoritative lifecycle/recovery protocol. Until
 * then both startup and idle passes preserve these datasets and report them.
 */
static int
reap_staging_walk(int dir_fd, int depth)
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
		int child;

		name = names[i];
		if (strncmp(name, info.zi_name, prefix_len) != 0 ||
		    name[prefix_len] != '/')
			continue;
		rel = name + prefix_len + 1;
		if (strchr(rel, '/') != NULL)
			continue;	/* only direct children */
		child = tzfs_openat(dir_fd, rel, ZH_ALL_RIGHTS, ZHF_SUBTREE);
		if (child == -1)
			continue;	/* raced away; nothing to reap */
		/* A reserved name is not proof of abandonment or successful
		 * publication. In particular del-<id> can be the only original
		 * claim after interruption between commit's two renames. Startup
		 * also runs on same-boot provider restart. Preserve both sides
		 * until an authoritative recovery protocol resolves ownership. */
		if (bsdfilesystem_is_version_id_name(rel) ||
		    strncmp(rel, BSDFILESYSTEM_STAGING_PREFIX,
		    sizeof(BSDFILESYSTEM_STAGING_PREFIX) - 1) == 0) {
			logcmp_log(LOG_WARNING,
			    "reclaim: preserving unresolved transaction dataset %s",
			    name);
			(void)close(child);
			errno = EBUSY;
			rc = -1;
			continue;
		}
		/* An ordinary claim/namespace dir: descend to reach its clones. */
		if (reap_staging_walk(child, depth + 1) == -1)
			rc = -1;
		(void)close(child);
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	return (rc);
}

/*
 * Startup inventory of transaction staging. Reserved transaction names are
 * retained and reported unresolved: startup is neither a durable commit record
 * nor proof that the original owner has died. In particular a del-<id> dataset
 * may be the only original claim after the first commit rename. A future
 * recovery protocol must resolve these identities before authorizing deletion.
 */
int
bsdfilesystem_reap_staging(struct bsdfilesystem_state *st)
{

	return (reap_staging_walk(st->persistent_fd, 0));
}

/* Idle inventory uses the same preservation rule as startup. */
int
bsdfilesystem_reap_idle_staging(struct bsdfilesystem_state *st)
{

	return (reap_staging_walk(st->persistent_fd, 0));
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
	int replacement;
	char wanted[BSDFILESYSTEM_NAME_MAX];

	/* A selected worker cannot replace its view through inherited roots.
	 * A new session requires a new supervised namespace selection. */
	if (st->worker_namespaces != NULL)
		return (errno = EOPNOTSUPP, -1);

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
	/* Acquisition may be denied or fail on storage/descriptor exhaustion.
	 * Keep the previous session intact until its replacement is usable. */
	replacement = bsdfilesystem_ensure_path(st->ephemeral_fd, wanted,
	    RETAIN_RIGHTS);
	if (replacement == -1)
		return (-1);
	if (st->lease_fd != -1)
		close(st->lease_fd);
	st->lease_fd = replacement;
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
			continue;	/* group containers: inventoried separately */
		if (strchr(rel, '/') == NULL)
			emit(emit_arg, rel);
	}
	bsdfilesystem_nvl_names_free(names, nnames);
	return (0);
}

/*
 * Catalogue absence is an observation, not persistent-data deletion authority.
 * Retained generations and recovery records may still reference this state.
 * Keep it until an authenticated retention/deletion protocol can prove release.
 */
static int
persistent_destroy(void *arg __unused, const char *owner)
{
	BSDFILESYSTEM_PROBE_RECLAIM_DESTROY(owner, EBUSY);
	syslog(LOG_WARNING,
	    "reclaim: retaining persistent namespace %s: deletion authority absent",
	    owner);
	return (errno = EBUSY, -1);
}

/*
 * Group containers (Data/Shared/<group>/) are inventoried BY MEMBERSHIP: one is an
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
groups_destroy(void *arg __unused, const char *group)
{
	BSDFILESYSTEM_PROBE_RECLAIM_DESTROY(group, EBUSY);
	syslog(LOG_WARNING,
	    "reclaim: retaining group container Shared/%s: deletion authority absent",
	    group);
	return (errno = EBUSY, -1);
}

/*
 * Acquire a complete owner view before allowing destructive reconciliation.
 * Apps may be absent on a system-only installation.  Run/live is a required
 * readiness gate: switchboard publishes it before launching providers.
 */
static int
reclaim_bundles(int root_fd, struct capreclaim *r, enum capreclaim_when when)
{
	static const char *paths[] = {
		"Capabilities/System", "Capabilities/Apps", "Capabilities/Run/live"
	};
	int fds[3] = { -1, -1, -1 };
	int error, result;
	unsigned i;

	if (r->stats != NULL)
		memset(r->stats, 0, sizeof(*r->stats));
	for (i = 0; i < nitems(fds); i++) {
		fds[i] = openat(root_fd, paths[i],
		    O_DIRECTORY | O_RDONLY | O_CLOEXEC);
		if (fds[i] == -1 && !(i == 1 && errno == ENOENT)) {
			error = errno;
			/* An unobserved interval cannot confirm prior absence. */
			capreclaim_fini(r);
			result = -1;
			goto out;
		}
	}
	for (i = 0; i < nitems(fds); i++) {
		r->sources[i].fd = fds[i];
		r->sources[i].strip_cap = i != 2;
	}
	r->nsources = nitems(fds);
	result = capreclaim_run(r, when);
	error = errno;
out:
	for (i = 0; i < nitems(fds); i++) {
		if (fds[i] != -1)
			(void)close(fds[i]);
		r->sources[i].fd = -1;
	}
	if (result == -1)
		errno = error;
	return (result);
}

#ifdef BSDFILESYSTEM_TESTING
int
bsdfilesystem_test_reclaim_bundles(int root_fd, struct capreclaim *r,
    enum capreclaim_when when)
{
	return (reclaim_bundles(root_fd, r, when));
}
#endif

/*
 * The reconcile loop: the container-model cleanup for persistent state.  Runs
 * in a forked child so it never blocks the serve loop.  It reopens owner
 * directories relative to its retained root descriptor in capability mode.
 * It compares owners against switchboard's published live set. BOOT reports
 * absence immediately; TIMER confirms it across two observations. Neither is
 * deletion authority: the persistent callbacks preserve the datasets and report
 * unresolved retention. Missing owner sources also prevent reconciliation.
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
	 * container must be reported -- opt out of the library's empty-set floor.
	 */
	g.allow_empty_live = true;

	for (;;) {
		{
			int n;

			n = reclaim_bundles(st->root_fd, &r, when);
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
			} else {
				/* Missing owner information restarts the grace window. */
				capreclaim_fini(&g);
			}
		}
		/* Report unresolved transaction staging on the timer cadence.
		 * Age and mount state do not authorize recursive reclamation. */
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

/*
 * Provision only beneath a delivered dataset capability. The caller retains
 * base_fd; this function retains only the selected children on success.
 */
int
bsdfilesystem_layout_provision_fd(struct bsdfilesystem_state *st, int base_fd)
{
	struct bsdfilesystem_config *cfg = &st->cfg;
	struct zfd_info_args info;
	struct zfd_stat_args stat;
	const char *persistent, *ephemeral;
	uint64_t syncval;
	int error;

	persistent = rel_under(cfg->base, cfg->persistent);
	ephemeral = rel_under(cfg->base, cfg->ephemeral);
	if (persistent == NULL || *persistent == '\0' || ephemeral == NULL ||
	    *ephemeral == '\0')
		return (errno = EINVAL, -1);
	if (st->persistent_fd != -1 || st->ephemeral_fd != -1 ||
	    st->boot_fd != -1)
		return (errno = EBUSY, -1);
	memset(&info, 0, sizeof(info));
	memset(&stat, 0, sizeof(stat));
	if (tzfs_info(base_fd, &info) == -1 || tzfs_stat(base_fd, &stat) == -1)
		return (-1);
	/* STAT also rejects pool handles; a pool root is not a data-subtree grant.
	 * The bootstrap issuer must bind the selected pool and dataset GUIDs to
	 * authenticated policy. Names here check the provider's layout agreement. */
	if (info.zi_valid != 1 || info.zi_pool_guid == 0 || info.zi_ds_guid == 0 ||
	    stat.zs_ds_guid != info.zi_ds_guid || info.zi_flags != ZHF_SUBTREE ||
	    (info.zi_rights & RETAIN_RIGHTS) != RETAIN_RIGHTS ||
	    strnlen(info.zi_name, sizeof(info.zi_name)) == sizeof(info.zi_name) ||
	    strcmp(info.zi_name, cfg->base) != 0 || strchr(info.zi_name, '/') == NULL)
		return (errno = EACCES, -1);

	/* No global mountpoint: clients reach anonymous mounts by descriptor.
	 * A failed namespace property is fatal, including on later boots. */
	if (tzfs_set_prop_string(base_fd, "mountpoint", "none") == -1 ||
	    tzfs_set_prop_uint64(base_fd, "canmount", 0) == -1)
		return (-1);
	st->persistent_fd = bsdfilesystem_ensure_path(base_fd, persistent,
	    RETAIN_RIGHTS);
	if (st->persistent_fd == -1)
		goto fail;
	st->ephemeral_fd = bsdfilesystem_ensure_path(base_fd, ephemeral,
	    RETAIN_RIGHTS);
	if (st->ephemeral_fd == -1)
		goto fail;
	if (strcmp(cfg->ephemeral_sync, "standard") == 0)
		syncval = 0;
	else if (strcmp(cfg->ephemeral_sync, "always") == 0)
		syncval = 1;
	else if (strcmp(cfg->ephemeral_sync, "disabled") == 0)
		syncval = 2;
	else {
		errno = EINVAL;
		goto fail;
	}
	if (tzfs_set_prop_uint64(st->ephemeral_fd, "sync", syncval) == -1 ||
	    reconcile_boot_generations(st) == -1)
		goto fail;
	syslog(LOG_INFO, "provisioned %s {persistent,ephemeral}", cfg->base);
	return (0);
fail:
	error = errno;
	if (st->boot_fd >= 0)
		(void)close(st->boot_fd);
	if (st->ephemeral_fd >= 0)
		(void)close(st->ephemeral_fd);
	if (st->persistent_fd >= 0)
		(void)close(st->persistent_fd);
	st->boot_fd = st->ephemeral_fd = st->persistent_fd = -1;
	return (errno = error, -1);
}

/* Legacy acquisition for non-BIP systems; provisioning uses the same boundary. */
int
bsdfilesystem_layout_provision(struct bsdfilesystem_state *st)
{
	const char *relative;
	int pool, root, base, result, error;

	relative = rel_under(st->cfg.pool, st->cfg.base);
	if (relative == NULL || *relative == '\0')
		return (errno = EINVAL, -1);
	pool = tzfs_pool_open_fd(st->zfs_fd, st->cfg.pool, RETAIN_RIGHTS);
	if (pool == -1)
		return (-1);
	root = tzfs_pool_root_open(pool, RETAIN_RIGHTS, ZHF_SUBTREE);
	error = errno;
	(void)close(pool);
	if (root == -1)
		return (errno = error, -1);
	base = bsdfilesystem_ensure_path(root, relative, RETAIN_RIGHTS);
	error = errno;
	(void)close(root);
	if (base == -1)
		return (errno = error, -1);
	result = bsdfilesystem_layout_provision_fd(st, base);
	error = errno;
	(void)close(base);
	return (errno = error, result);
}
