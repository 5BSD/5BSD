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
#include <stdlib.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <trustedzfs.h>

#include "tzfsd.h"

extern char **environ;

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
	qsort(children, count, sizeof(*children), path_deepest_first);
	for (i = 0; i < count; i++) {
		if (tzfs_destroy(target, children[i]) == -1 && errno != ENOENT) {
			saved = errno;
			goto out;
		}
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
	if (zpd == -1) {
		syslog(LOG_ERR, "pool_open %s: %m", cfg->pool);
		return (-1);
	}
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
	 * on every reboot the persisted datasets are OS-mounted before serviced
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
		 * propagates to the whole subtree by inheritance and unmounts any
		 * OS-mounted members. */
		if (tzfs_set_prop_string(base_fd, "mountpoint", "none") == -1)
			syslog(LOG_WARNING, "set mountpoint=none on %s: %m "
			    "(datasets may be OS-mounted and collide after reboot)",
			    cfg->base);
		if (tzfs_set_prop_uint64(base_fd, "canmount", 0) == -1)
			syslog(LOG_WARNING, "set canmount=off on %s: %m", cfg->base);
		else
			(void)tzfs_unmount(base_fd);
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
