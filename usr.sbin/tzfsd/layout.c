/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) layout provisioning.  Everything here runs before cap_enter(): it
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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <trustedzfs.h>
#include <capreclaim.h>

#include "tzfsd.h"
#include "tzfsd_probes.h"

extern char **environ;

/*
 * The container-model live set (docs/capability-container-model.md): the
 * installed bundles are the pkg-owned System/ and Apps/ directories (read
 * directly -- they are always authoritative, so no marker or sentinel is
 * needed), and switchboard adds a marker per running bundle under Run/live/ so a
 * unit that is up but whose bundle is mid-removal is never reaped.  The reconcile
 * reaps a Data/<bundle> container only when its bundle is in none of the three.
 * System/ existing is the readiness gate: while it cannot be opened the reconcile
 * reaps nothing.
 */
#define	TZFSD_SYSTEM_DIR	"/Capabilities/System"
#define	TZFSD_APPS_DIR		"/Capabilities/Apps"
#define	TZFSD_RUN_LIVE_DIR	"/Capabilities/Run/live"
#define	TZFSD_RUN_GROUPS_DIR	"/Capabilities/Run/groups"	/* installed-claimed groups */
#define	TZFSD_SHARED_DIR	"Shared"	/* Data/Shared/<group>/ containers */
#define	TZFSD_RECLAIM_POLL	3	/* while still awaiting the first pass */

#define	RETAIN_RIGHTS	ZH_ALL_RIGHTS
#define	ZFS_DEV_PATH	"/dev/zfs"

/* Run a command to completion; return its exit status, or -1 to spawn. */
static int
run(char *const argv[])
{
	posix_spawn_file_actions_t fa;
	pid_t pid;
	int rc, status;

	(void)posix_spawn_file_actions_init(&fa);
	/* Keep the child quiet; its diagnostics are best-effort here. */
	(void)posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO,
	    "/dev/null", O_WRONLY, 0);
	(void)posix_spawn_file_actions_addopen(&fa, STDERR_FILENO,
	    "/dev/null", O_WRONLY, 0);
	rc = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
	posix_spawn_file_actions_destroy(&fa);
	if (rc != 0) {
		errno = rc;
		return (-1);
	}
	if (waitpid(pid, &status, 0) == -1)
		return (-1);
	return (WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

/*
 * Make ZFS usable before anything opens it.  tzfsd runs early in the PID 1
 * chain (and the host may be UFS-rooted), so it must not assume rc(8) has
 * loaded the module or imported the pool.  Both steps are idempotent and
 * best-effort: if ZFS is already up, these are no-ops; loader.conf's
 * zfs_load="YES" normally means the module is already present.
 */
int
tzfsd_ensure_zfs(struct tzfsd_config *cfg)
{
	char *imp_argv[5];
	int i;

	/* 1. Module: load zfs.ko if /dev/zfs is absent, then wait for devfs. */
	if (access(ZFS_DEV_PATH, F_OK) != 0) {
		if (kldload("zfs") == -1 && errno != EEXIST)
			syslog(LOG_WARNING, "kldload zfs: %m");
		for (i = 0; i < 50 && access(ZFS_DEV_PATH, F_OK) != 0; i++) {
			struct timespec ts = { 0, 20 * 1000 * 1000 }; /* 20ms */
			(void)nanosleep(&ts, NULL);
		}
		if (access(ZFS_DEV_PATH, F_OK) != 0) {
			syslog(LOG_ERR, "%s never appeared", ZFS_DEV_PATH);
			errno = ENXIO;
			return (-1);
		}
		syslog(LOG_INFO, "loaded zfs.ko");
	}

	/*
	 * 2. Pool: if the capability pool is not imported yet, import it
	 * without mounting (we hand out handles / anonymous mounts).  An
	 * already-imported pool makes `zpool import` a harmless no-op.
	 */
	imp_argv[0] = __DECONST(char *, "zpool");
	imp_argv[1] = __DECONST(char *, "import");
	imp_argv[2] = __DECONST(char *, "-N");
	imp_argv[3] = cfg->pool;
	imp_argv[4] = NULL;
	(void)run(imp_argv);		/* best-effort; provision verifies */
	return (0);
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
tzfsd_pool_missing_expected(int error)
{
	struct statfs fs;

	if (statfs("/", &fs) == -1)
		return (false);
	return (pool_missing_expected(fs.f_fstypename, fs.f_flags, error));
}

#ifdef TZFSD_TESTING
bool
tzfsd_test_pool_missing_expected(const char *fstype, uint64_t flags, int error)
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
tzfsd_ensure_path(int root_fd, const char *relpath, uint64_t rights)
{
	char comp[TZFSD_MAXPATH];
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
 * Return true only for an old, globally visible mount of the capability
 * dataset or one of its descendants.  Anonymous mounts are the live data
 * plane: they are deliberately reported as "[anon]" and must survive a
 * tzfsd restart.
 */
static bool
legacy_global_mount(const char *base, const char *fstype, const char *from,
    const char *on)
{
	size_t len;

	if (base == NULL || base[0] == '\0' || fstype == NULL || from == NULL ||
	    on == NULL ||
	    strcmp(fstype, "zfs") != 0 || strcmp(on, "[anon]") == 0)
		return (false);
	len = strlen(base);
	return (strncmp(from, base, len) == 0 &&
	    (from[len] == '\0' || from[len] == '/'));
}

#ifdef TZFSD_TESTING
bool
tzfsd_test_legacy_global_mount(const char *base, const char *fstype,
    const char *from, const char *on)
{

	return (legacy_global_mount(base, fstype, from, on));
}
#endif

/*
 * A pre-migration `zfs mount -a` may already have mounted descendants before
 * we change the inherited mountpoint to none.  Changing the property does not
 * detach those existing mounts, and they make stale-generation destruction
 * fail with EBUSY.  Detach only global mounts from the reserved capability
 * subtree, deepest-first; never touch anonymous mounts owned by live clients.
 */
static void
unmount_legacy_global_mounts(const char *base)
{
	struct statfs *mntbuf;
	char **mounts;
	size_t count, i;
	int nmounts;

	nmounts = getmntinfo(&mntbuf, MNT_NOWAIT);
	if (nmounts == 0) {
		syslog(LOG_WARNING, "enumerate mounts while provisioning %s: %m",
		    base);
		return;
	}
	mounts = calloc((size_t)nmounts, sizeof(*mounts));
	if (mounts == NULL) {
		syslog(LOG_WARNING, "allocate mount migration list for %s: %m",
		    base);
		return;
	}
	count = 0;
	for (i = 0; i < (size_t)nmounts; i++) {
		if (!legacy_global_mount(base, mntbuf[i].f_fstypename,
		    mntbuf[i].f_mntfromname, mntbuf[i].f_mntonname))
			continue;
		mounts[count] = strdup(mntbuf[i].f_mntonname);
		if (mounts[count] == NULL) {
			syslog(LOG_WARNING,
			    "copy legacy mount path while provisioning %s: %m", base);
			continue;
		}
		count++;
	}
	qsort(mounts, count, sizeof(*mounts), path_deepest_first);
	for (i = 0; i < count; i++) {
		if (unmount(mounts[i], 0) == -1 && errno != EINVAL &&
		    errno != ENOENT)
			syslog(LOG_WARNING, "unmount legacy capability mount %s: %m",
			    mounts[i]);
		free(mounts[i]);
	}
	free(mounts);
}

/*
 * Destroy every snapshot of the dataset behind `target` (a full-rights
 * handle).  The kernel lists snapshots by full name ("pool/a/b@snap"); the
 * per-handle destroy verb takes the bare snapshot name after the '@'.
 * Returns 0 when none remain, -1 with errno (EBUSY for a cloned snapshot)
 * on the first failure.
 */
int
tzfsd_destroy_snapshots(int target)
{
	void *buf;
	char **names;
	const char *at;
	size_t len, nnames, i;
	int saved;

	if (tzfs_list_snapshots(target, &buf, &len) == -1)
		return (-1);
	if (tzfsd_nvl_names(buf, len, &names, &nnames) == -1) {
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
			syslog(LOG_WARNING, "reclaim: destroy snapshot %s: %m%s",
			    names[i], saved == EEXIST ?
			    " (a clone depends on it)" : "");
			break;
		}
		TZFSD_PROBE_RECLAIM_SNAPSHOT(names[i]);
	}
	tzfsd_nvl_names_free(names, nnames);
	if (saved != 0) {
		errno = saved;
		return (-1);
	}
	return (0);
}

/* Destroy one capability-owned subtree, deepest datasets first. */
int
tzfsd_destroy_tree(int parent_fd, const char *relname)
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
	if (tzfsd_nvl_names(buf, len, &names, &nnames) == -1) {
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
		tzfsd_nvl_names_free(names, nnames);
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
		if (tzfsd_destroy_tree(target, children[i]) == -1) {
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
	if (tzfsd_destroy_snapshots(target) == -1) {	/* EEXIST: cloned */
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
	tzfsd_nvl_names_free(names, nnames);
	if (target != -1)
		close(target);
	if (saved != 0) {
		errno = saved;
		return (-1);
	}
	return (0);
}

static int
reconcile_boot_generations(struct tzfsd_state *st)
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
	if (tzfsd_nvl_names(buf, len, &names, &nnames) == -1) {
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
		    tzfsd_destroy_tree(st->ephemeral_fd, rel) == -1) {
			syslog(LOG_WARNING, "reconcile stale boot storage %s: %m",
			    rel);
		}
	}
	tzfsd_nvl_names_free(names, nnames);
	st->boot_fd = tzfsd_ensure_path(st->ephemeral_fd, st->boot_name,
	    RETAIN_RIGHTS);
	return (st->boot_fd == -1 ? -1 : 0);
}

/*
 * Reap orphaned ephemeral leases.  A lease (ephemeral/lease-<session>) is bound
 * to the lifetime of the connection that began it.  Called once at daemon
 * startup, before any connection is served: no lease has a live owner yet, so
 * every lease-* under ephemeral is an orphan left by a prior boot and is
 * destroyed.  This is the boot-scoped GC that tzfsd_session_begin used to do by
 * reaping "every lease but mine" — which is unsafe once concurrent connections
 * each own their own lease, so it lives here instead.
 */
int
tzfsd_reap_leases(struct tzfsd_state *st)
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
	if (tzfsd_nvl_names(buf, len, &names, &nnames) == -1) {
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
		    tzfsd_destroy_tree(st->ephemeral_fd, rel) == -1) {
			rc = -1;
			break;
		}
	}
	tzfsd_nvl_names_free(names, nnames);
	return (rc);
}

/*
 * Begin (create or open) this connection's ephemeral lease.  Each live
 * connection owns exactly one lease-<session> and this NEVER reaps another
 * connection's lease: concurrent consumers must not delete one another's
 * storage.  Leases orphaned across a reboot are cleared by tzfsd_reap_leases()
 * at startup.
 */
int
tzfsd_session_begin(struct tzfsd_state *st, const char *session)
{
	const char *p;
	char wanted[TZFSD_NAME_MAX];

	if (session == NULL || strlen(session) != TZFSD_SESSION_MAX - 1) {
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
	st->lease_fd = tzfsd_ensure_path(st->ephemeral_fd, wanted,
	    RETAIN_RIGHTS);
	if (st->lease_fd == -1)
		return (-1);
	strlcpy(st->lease_name, wanted, sizeof(st->lease_name));
	return (0);
}

/*
 * libcapreclaim enumerate callback: emit every per-bundle container tzfsd holds,
 * by its top-level bundle name.  Durable data lives at Data/<bundle>/<unit>/...,
 * so the direct children of the Data root are the bundle names -- exactly the
 * key the reconcile compares against the installed bundle set (System/, Apps/).
 * Mirrors tzfsd_reap_leases: list the children of the retained Data parent and
 * keep only the single top-level component (a nested unit/persistent dataset is
 * not itself a container).
 */
static int
persistent_enumerate(void *arg,
    void (*emit)(void *emit_arg, const char *owner), void *emit_arg)
{
	struct tzfsd_state *st = arg;
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
	if (tzfsd_nvl_names(buf, len, &names, &nnames) == -1) {
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
		if (strcmp(rel, TZFSD_SHARED_DIR) == 0)
			continue;	/* group containers: reaped by membership */
		if (strchr(rel, '/') == NULL)
			emit(emit_arg, rel);
	}
	tzfsd_nvl_names_free(names, nnames);
	return (0);
}

/*
 * libcapreclaim destroy callback: reap one gone owner's entire persistent
 * namespace, deepest dataset first, exactly as OP_DESTROY/reclaim do.  The
 * owner key is a single '/'-free component, and tzfsd_destroy_tree refuses any
 * relname bearing a '/', so this can only ever touch derive_ns(owner)'s subtree.
 */
static int
persistent_destroy(void *arg, const char *owner)
{
	struct tzfsd_state *st = arg;
	int rc;

	rc = tzfsd_destroy_tree(st->persistent_fd, owner);
	TZFSD_PROBE_RECLAIM_DESTROY(owner, rc == 0 ? 0 : errno);
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
	struct tzfsd_state *st = arg;
	struct zfd_info_args info;
	void *buf;
	char **names;
	size_t len, nnames, prefix_len, i;
	int shared_fd, saved;

	if (st->persistent_fd == -1)
		return (0);
	shared_fd = tzfs_openat(st->persistent_fd, TZFSD_SHARED_DIR,
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
	if (tzfsd_nvl_names(buf, len, &names, &nnames) == -1) {
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
	tzfsd_nvl_names_free(names, nnames);
	return (0);
}

static int
groups_destroy(void *arg, const char *group)
{
	struct tzfsd_state *st = arg;
	int shared_fd, rc, saved;

	shared_fd = tzfs_openat(st->persistent_fd, TZFSD_SHARED_DIR,
	    ZH_ALL_RIGHTS, ZHF_SUBTREE);
	if (shared_fd == -1)
		return (errno == ENOENT ? 0 : -1);
	rc = tzfsd_destroy_tree(shared_fd, group);
	saved = errno;
	close(shared_fd);
	TZFSD_PROBE_RECLAIM_DESTROY(group, rc == 0 ? 0 : saved);
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
tzfsd_reaper_loop(struct tzfsd_state *st)
{
	struct capreclaim r, g;
	struct capreclaim_stats stats, gstats;
	enum capreclaim_when when = CAPRECLAIM_BOOT, gwhen = CAPRECLAIM_BOOT;
	unsigned nap, gpolls = 0;

	setproctitle("-Filesystem[reclaim]");
	memset(&r, 0, sizeof(r));
	r.enumerate = persistent_enumerate;
	r.destroy = persistent_destroy;
	r.arg = st;
	r.stats = &stats;
	memset(&g, 0, sizeof(g));
	g.enumerate = groups_enumerate;
	g.destroy = groups_destroy;
	g.arg = st;
	g.stats = &gstats;
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
		sys_fd = open(TZFSD_SYSTEM_DIR, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
		if (sys_fd != -1) {
			int n;

			apps_fd = open(TZFSD_APPS_DIR,
			    O_DIRECTORY | O_RDONLY | O_CLOEXEC);
			run_fd = open(TZFSD_RUN_LIVE_DIR,
			    O_DIRECTORY | O_RDONLY | O_CLOEXEC);
			r.sources[0].fd = sys_fd;
			r.sources[0].strip_cap = true;	/* System/<Bundle>.cap */
			r.sources[1].fd = apps_fd;	/* -1 if absent: skipped */
			r.sources[1].strip_cap = true;	/* Apps/<Bundle>.cap */
			r.sources[2].fd = run_fd;	/* -1 if absent: skipped */
			r.sources[2].strip_cap = false;	/* Run/live/<bundle> */
			r.nsources = 3;
			n = capreclaim_run(&r, when);
			TZFSD_PROBE_RECLAIM_PASS((int)when, stats.nlive,
			    stats.nowned, stats.norphans, stats.ndestroyed,
			    stats.nfailed);
			if (n == -1)
				syslog(LOG_WARNING, "reclaim: %s pass failed: %m",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer");
			else if (n > 0 || stats.nfailed > 0)
				syslog(LOG_NOTICE,
				    "reclaim: %s pass reaped %d orphan%s (%u live, "
				    "%u owned, %u orphaned, %u failed)",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer",
				    n, n == 1 ? "" : "s", stats.nlive, stats.nowned,
				    stats.norphans, stats.nfailed);
			if (n >= 0)
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
			int groups_fd = open(TZFSD_RUN_GROUPS_DIR,
			    O_DIRECTORY | O_RDONLY | O_CLOEXEC);

			if (groups_fd != -1) {
				int n;

				g.sources[0].fd = groups_fd;
				g.sources[0].strip_cap = false;
				g.nsources = 1;
				n = capreclaim_run(&g, gwhen);
				TZFSD_PROBE_RECLAIM_PASS((int)gwhen + 2, gstats.nlive,
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
				if (n >= 0)
					gwhen = CAPRECLAIM_TIMER;
				(void)close(groups_fd);
			}
		}
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
		    (gwhen == CAPRECLAIM_BOOT && gpolls++ < 60)) ? TZFSD_RECLAIM_POLL :
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
tzfsd_start_reaper(struct tzfsd_state *st)
{
	pid_t pid;

	if (st->persistent_fd == -1)
		return;				/* no persistent state to reap */
	pid = fork();
	if (pid == -1) {
		syslog(LOG_WARNING, "reclaim: fork: %m");
		return;
	}
	if (pid == 0) {
		(void)signal(SIGCHLD, SIG_DFL);
		tzfsd_reaper_loop(st);
		/* NOTREACHED */
	}
}

int
tzfsd_layout_provision(struct tzfsd_state *st)
{
	struct tzfsd_config *cfg = &st->cfg;
	const char *rel;
	int zpd, root_fd;

	/*
	 * Pool root handle: the anchor for the whole /Capabilities tree.  The
	 * pool handle must hold at least the rights we then derive for the root
	 * dataset handle (pool_root_open requires a subset), so open it with the
	 * full mask; tzfsd runs as root and owns the storage plane.
	 */
	zpd = tzfs_pool_open(cfg->pool, RETAIN_RIGHTS);
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
	 * management.  tzfsd's datasets are reached exclusively through capability
	 * handles and ANONYMOUS mounts (ZFD_MOUNT / ZH_MOUNT: the objset is mounted
	 * without any global-namespace mountpoint and accessed only through the
	 * returned dir fd — see sys/sys/zfshandle.h).  They must therefore never be
	 * mounted by the OS's boot-time `zfs mount -a`.  If the OS mounts one at its
	 * inherited mountpoint, the objset is already mounted, and tzfsd's anonymous
	 * mount (and any destroy) of the SAME dataset fails EBUSY.  That is the
	 * second-boot collision: on a fresh boot the datasets do not exist yet, but
	 * on every reboot the persisted datasets are OS-mounted before switchboard
	 * runs, so a reused persistent claim makes the consumer's storage request
	 * fail EBUSY (a crash-looping logd) and a stale ephemeral generation makes
	 * the reconcile destroy fail EBUSY.
	 *
	 * Setting the base dataset's mountpoint to "none" propagates by inheritance
	 * to every child — persistent, ephemeral, per-service homes and claims,
	 * boot/lease generations — so the OS mounts none of them, and tzfsd owns the
	 * (anonymous) mount lifecycle completely.  It also keeps the static
	 * /Capabilities/System bundle tree visible, since the base is not mounted
	 * over the root dataset's /Capabilities.  canmount=off is kept as belt-and-
	 * suspenders on the base itself (integer-encoded property, so the uint64
	 * setter — the string path panics ZFS on an int property).  The unmount is
	 * best-effort self-healing for a subtree left mounted by an older tzfsd.
	 */
	rel = rel_under(cfg->pool, cfg->base);
	if (rel != NULL) {
		int base_fd = tzfsd_ensure_path(root_fd, rel, RETAIN_RIGHTS);

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
		unmount_legacy_global_mounts(cfg->base);
		(void)close(base_fd);
	}

	/* base/persistent/ephemeral all hang under the pool root. */
	rel = rel_under(cfg->pool, cfg->persistent);
	if (rel == NULL ||
	    (st->persistent_fd = tzfsd_ensure_path(root_fd, rel, RETAIN_RIGHTS)) ==
	    -1) {
		syslog(LOG_ERR, "provision %s: %m", cfg->persistent);
		(void)close(root_fd);
		return (-1);
	}
	rel = rel_under(cfg->pool, cfg->ephemeral);
	if (rel == NULL ||
	    (st->ephemeral_fd = tzfsd_ensure_path(root_fd, rel, RETAIN_RIGHTS)) ==
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
		syslog(LOG_ERR, "provision current boot storage: %m");
		return (-1);
	}

	syslog(LOG_INFO, "provisioned %s {persistent,ephemeral}",
	    cfg->base);
	return (0);
}
