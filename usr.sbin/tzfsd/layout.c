/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) layout provisioning and flavor preparation.  Everything here runs
 * before cap_enter(): it opens handles by name (tzfs_open needs /dev/zfs) and
 * may spawn a decompressor to receive a baked template send-stream.  The
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
#define	ZSTD_PATH	"/usr/bin/zstd"
#define	TZFSD_NATIVE_SNAP	"tzfs-native"	/* BE snapshot cloned for native */

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

int
tzfsd_session_begin(struct tzfsd_state *st, const char *session)
{
	struct zfd_info_args info;
	void *buf;
	char **names;
	const char *name, *rel, *p;
	char wanted[TZFSD_NAME_MAX];
	size_t len, prefix_len, nnames, i;

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
		    strcmp(rel, wanted) != 0 &&
		    tzfsd_destroy_tree(st->ephemeral_fd, rel) == -1) {
			tzfsd_nvl_names_free(names, nnames);
			return (-1);
		}
	}
	tzfsd_nvl_names_free(names, nnames);
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

	/* base/persistent/ephemeral/templates all hang under the pool root. */
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
	rel = rel_under(cfg->pool, cfg->templates);
	if (rel == NULL ||
	    (st->templates_fd = tzfsd_ensure_path(root_fd, rel, RETAIN_RIGHTS)) ==
	    -1) {
		syslog(LOG_ERR, "provision %s: %m", cfg->templates);
		(void)close(root_fd);
		return (-1);
	}
	(void)close(root_fd);
	if (reconcile_boot_generations(st) == -1) {
		syslog(LOG_ERR, "provision current boot storage: %m");
		return (-1);
	}

	syslog(LOG_INFO, "provisioned %s {persistent,ephemeral,.templates}",
	    cfg->base);
	return (0);
}

/* Create template@ready, tolerating an existing snapshot. */
static int
ensure_ready_snap(int tmpl_fd)
{

	if (tzfs_snapshot(tmpl_fd, TZFSD_TEMPLATE_SNAP) == -1 &&
	    errno != EEXIST)
		return (-1);
	return (0);
}

/*
 * Receive a baked send-stream into templates/<name>.  The artifact is
 * zstd-compressed; decompress it through a spawned `zstd -dc` whose stdout is
 * the recv input.  Returns 0 on success, -1 otherwise.
 */
static int
recv_baked(int templates_fd, struct tzfsd_flavor_def *f)
{
	posix_spawn_file_actions_t fa;
	struct stat sb;
	char *argv[4];
	pid_t pid, waited;
	bool fa_initialized;
	int error, pipefd[2], srcfd, rc, status;

	srcfd = open(f->source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (srcfd == -1)
		return (-1);
	if (fstat(srcfd, &sb) == -1) {
		error = errno;
		(void)close(srcfd);
		errno = error;
		return (-1);
	}
	if (!S_ISREG(sb.st_mode) || sb.st_size == 0 || sb.st_uid != 0 ||
	    (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		(void)close(srcfd);
		errno = EPERM;
		return (-1);
	}
	if (pipe2(pipefd, O_CLOEXEC) == -1) {
		(void)close(srcfd);
		return (-1);
	}

	fa_initialized = false;
	rc = posix_spawn_file_actions_init(&fa);
	if (rc == 0)
		fa_initialized = true;
	if (rc == 0)
		rc = posix_spawn_file_actions_adddup2(&fa, srcfd, STDIN_FILENO);
	if (rc == 0)
		rc = posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
	argv[0] = __DECONST(char *, ZSTD_PATH);
	argv[1] = __DECONST(char *, "-dc");
	argv[2] = NULL;
	if (rc == 0)
		rc = posix_spawn(&pid, ZSTD_PATH, &fa, NULL, argv, environ);
	if (fa_initialized)
		(void)posix_spawn_file_actions_destroy(&fa);
	(void)close(srcfd);
	(void)close(pipefd[1]);
	if (rc != 0) {
		(void)close(pipefd[0]);
		errno = rc;
		return (-1);
	}

	/*
	 * The recv target is a snapshot name: a full send stream creates the
	 * dataset and its @ready snapshot together (ZFD_RECV rejects a bare
	 * dataset name).  mkflavor sends @ready, so receive templates/<flavor>
	 * @ready.
	 */
	{
		char target[TZFSD_FLAVOR_MAX + sizeof(TZFSD_TEMPLATE_SNAP) + 1];

		(void)snprintf(target, sizeof(target), "%s@%s", f->name,
		    TZFSD_TEMPLATE_SNAP);
		rc = tzfs_recv(templates_fd, target, pipefd[0], false);
	}
	if (rc == -1)
		syslog(LOG_ERR, "recv %s from %s: %m", f->name, f->source);
	(void)close(pipefd[0]);
	do {
		waited = waitpid(pid, &status, 0);
	} while (waited == -1 && errno == EINTR);
	if (waited == -1) {
		if (rc == 0)
			rc = -1;
	} else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		if (rc == 0)
			errno = EIO;
		rc = -1;
	}
	if (rc == -1)
		return (-1);
	return (0);
}

/*
 * Build the "native" template as a copy-on-write clone of the running boot
 * environment (the dataset mounted at "/").  This costs essentially no image
 * space: the template shares blocks with the live root until a capability
 * cloned from it diverges, so native ships "for free" rather than as a baked
 * second copy of the system.  The pinned BE snapshot is created once, on the
 * first start that materializes the template; later starts take the "already
 * present" path and never re-enter here.  Returns 0 on success, -1 otherwise.
 */
static int
build_native_live(struct tzfsd_state *st, struct tzfsd_flavor_def *f)
{
	struct tzfsd_config *cfg = &st->cfg;
	struct statfs sfs;
	const char *be, *rel;
	size_t plen;
	int zpd, root_fd, be_fd, tmpl_fd, ok = -1;

	if (statfs("/", &sfs) != 0)
		return (-1);
	be = sfs.f_mntfromname;		/* e.g. "zroot" or "zroot/ROOT/default" */

	/* The boot environment must live in our configured pool. */
	plen = strlen(cfg->pool);
	if (strncmp(be, cfg->pool, plen) != 0 ||
	    (be[plen] != '\0' && be[plen] != '/'))
		return (-1);
	rel = (be[plen] == '/') ? be + plen + 1 : "";

	zpd = tzfs_pool_open(cfg->pool, RETAIN_RIGHTS);
	if (zpd == -1)
		return (-1);
	root_fd = tzfs_pool_root_open(zpd, RETAIN_RIGHTS, ZHF_SUBTREE);
	(void)close(zpd);
	if (root_fd == -1)
		return (-1);

	if (rel[0] == '\0') {
		be_fd = root_fd;
	} else {
		be_fd = tzfs_openat(root_fd, rel, RETAIN_RIGHTS, 0);
		if (be_fd == -1) {
			(void)close(root_fd);
			return (-1);
		}
	}

	/* Snapshot the live BE (idempotent) and clone it into the template. */
	if (tzfs_snapshot(be_fd, TZFSD_NATIVE_SNAP) == -1 && errno != EEXIST)
		goto out;
	tmpl_fd = tzfs_clone(st->templates_fd, be_fd, TZFSD_NATIVE_SNAP,
	    f->name);
	if (tmpl_fd == -1) {
		syslog(LOG_ERR, "native: clone %s@%s: %m", be,
		    TZFSD_NATIVE_SNAP);
		goto out;
	}
	if (ensure_ready_snap(tmpl_fd) == 0)
		ok = 0;
	(void)close(tmpl_fd);
out:
	if (be_fd != root_fd)
		(void)close(be_fd);
	(void)close(root_fd);
	return (ok);
}

/*
 * Make each enabled flavor's template available, per its build mode and the
 * precedence in docs/tzfsd-design.md §3.1.  Sets f->available.  A flavor that
 * cannot be made ready is simply left unavailable (and thus not offered).
 */
int
tzfsd_flavors_prepare(struct tzfsd_state *st)
{
	struct tzfsd_config *cfg = &st->cfg;
	unsigned i, navail = 0;

	for (i = 0; i < cfg->nflavors; i++) {
		struct tzfsd_flavor_def *f = &cfg->flavors[i];
		int tmpl_fd;

		f->available = false;
		if (!f->enabled)
			continue;

		/* Already present? Ensure its @ready snapshot and offer it. */
		tmpl_fd = tzfs_openat(st->templates_fd, f->name,
		    ZH_SNAPSHOT | ZH_PROPS_READ, 0);
		if (tmpl_fd != -1) {
			if (ensure_ready_snap(tmpl_fd) == 0)
				f->available = true;
			(void)close(tmpl_fd);
			if (f->available)
				navail++;
			continue;
		}

		/* Not present: materialize by build mode. */
		if (f->build == TZFSD_BUILD_LIVE &&
		    strcmp(f->name, "empty") == 0) {
			tmpl_fd = tzfs_create(st->templates_fd, f->name, 0);
			if (tmpl_fd != -1) {
				if (ensure_ready_snap(tmpl_fd) == 0)
					f->available = true;
				(void)close(tmpl_fd);
			}
		} else if (f->build == TZFSD_BUILD_LIVE) {
			/* native: clone the running boot environment. */
			if (build_native_live(st, f) == 0)
				f->available = true;
		} else if (f->build == TZFSD_BUILD_BAKED) {
			if (recv_baked(st->templates_fd, f) == 0) {
				tmpl_fd = tzfs_openat(st->templates_fd,
				    f->name, ZH_SNAPSHOT | ZH_PROPS_READ, 0);
				if (tmpl_fd != -1) {
					if (ensure_ready_snap(tmpl_fd) == 0)
						f->available = true;
					(void)close(tmpl_fd);
				}
			}
		}
		/*
		 * SOURCE fetch (fetch/unpack from a URL) is not yet
		 * implemented; such flavors are offered only if their template
		 * was pre-seeded (handled by the "already present" branch
		 * above).  empty and native are built live; freebsd/linux are
		 * baked.
		 */
		if (f->available)
			navail++;
		else
			syslog(LOG_NOTICE, "flavor %s unavailable (no template)",
			    f->name);
	}
	syslog(LOG_INFO, "%u/%u flavors available", navail, cfg->nflavors);
	return (0);
}
