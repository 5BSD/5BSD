/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdfilesystem(8) — the [TZFS] storage daemon.
 *
 * Owns the storage plane: the root-pool handle and the /Capabilities layout.
 * It mints rights-limited TrustedZFS handles on request and passes them back
 * over its clients' mac_capability channels.  bsdfilesystem is a socket-free
 * service_provider: it exposes the well-known name system.Filesystem and serves
 * each client on its own worker channel, exactly like every other
 * capability-plane daemon. The maintained unit is born in capability mode,
 * with explicit directory resources for configuration and device acquisition.
 * In the serving window every operation is an ioctl on a held, cap_ioctls-limited
 * TrustedZFS handle (dataset create/destroy/mount/unmount are ZFD_* ioctls, never
 * mount(2)) or an openat(2) beneath the retained root fd with
 * O_RESOLVE_BENEATH/O_NOFOLLOW -- so containment is both capsicum AND the
 * per-container scoping stamped on each channel.
 */

#include <sys/types.h>
#include <sys/zfshandle.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>

#include "bsdfilesystem.h"

static void
usage(void)
{

	(void)fprintf(stderr, "usage: bsdfilesystem [-c config]\n");
	exit(1);
}

/*
 * Guarantee fds 0/1/2 are open before any capability handle is created, so a
 * handle can never occupy a stdio slot.  bsdfilesystem is launched by switchboard without
 * a controlling terminal: a capability handle that landed on fd 0/1/2 could be
 * clobbered by a later /dev/null redirect, and every subsequent ZFD_* on it
 * would fail.
 */
static void
reserve_stdio(void)
{
	int fd, nfd;

	for (fd = 0; fd <= 2; fd++) {
		if (fcntl(fd, F_GETFD) != -1)
			continue;
		nfd = open("/dev/null", O_RDWR);
		if (nfd == -1)
			continue;
		if (nfd != fd) {
			(void)dup2(nfd, fd);
			(void)close(nfd);
		}
	}
}

#ifndef BSDFILESYSTEM_TESTING
int
main(int argc, char **argv)
{
	struct bsdfilesystem_state st;
	struct stat policy_stat;
	const char *conf = NULL;
	bool storage_available;
	int ch, cfgfd, dev_dirfd;

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			conf = optarg;
			break;
		default:
			usage();
		}
	}

	/*
	 * LOG_PERROR unconditionally: switchboard captures the copies on the
	 * launching side; there is no controlling terminal in production.
	 */
	openlog("bsdfilesystem", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	/* Before opening any capability handle (see reserve_stdio). */
	reserve_stdio();

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = -1;
	st.root_fd = -1;
	st.zfs_fd = -1;

	/*
	 * bsdfilesystem is BORN IN CAPABILITY MODE: switchboard cap_enter()s before
	 * exec, so it opens nothing by global path.  Its privileged, name-based
	 * bootstrap resources are delivered as inherited directory descriptors --
	 * "/" (the isolated-open base, the operator-config base, and the reclaim
	 * child's install-dir base) and /dev (for the ZFS control device). The
	 * provider can acquire an already-imported pool there. Derived
	 * handles are authorized by handle rights, not UNIX privilege.
	 */
	if (service_resource_dir("/", &st.root_fd) == -1) {
		syslog(LOG_WARNING, "no delivered root directory; isolated-open and "
		    "operator config unavailable: %m");
		st.root_fd = -1;
	}

	/* Supplied policy is data only; parse/read errors are fatal. */
	bsdfilesystem_config_defaults(&st.cfg);
	if (conf != NULL)
		cfgfd = open(conf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
		    O_VERIFY | O_NONBLOCK);
	else if (st.root_fd != -1)
		cfgfd = openat(st.root_fd, "Capabilities/Config/bsdfilesystem.ucl",
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_VERIFY | O_NONBLOCK);
	else {
		cfgfd = -1;
		errno = ENOENT;
	}
	if (cfgfd < 0) {
		if (conf != NULL || errno != ENOENT) {
			syslog(LOG_ERR, "required storage policy unavailable: %m");
			return (1);
		}
	} else if (conf != NULL && (fstat(cfgfd, &policy_stat) == -1 ||
	    policy_stat.st_uid != geteuid() || (policy_stat.st_mode & 022) != 0)) {
		(void)close(cfgfd);
		syslog(LOG_ERR, "explicit storage policy has untrusted ownership or mode");
		return (1);
	} else if (bsdfilesystem_config_load_fd(&st.cfg, cfgfd) == -1) {
		syslog(LOG_ERR, "storage policy rejected: %m");
		return (1);
	}

	/*
	 * ZFS control device via the delivered /dev directory.  Storage is
	 * unavailable on installer media (no root pool) or when /dev was not
	 * delivered; keep serving policy-gated isolated-open in that case (dataset
	 * ops fail closed with ENXIO when their parents are absent).
	 */
	storage_available = false;
	dev_dirfd = -1;
	if (service_resource_dir("/dev", &dev_dirfd) == -1) {
		syslog(LOG_WARNING, "no delivered /dev; serving isolated paths only: %m");
	} else if ((st.zfs_fd = bsdfilesystem_ensure_zfs(dev_dirfd)) == -1) {
		syslog(LOG_WARNING, "ZFS unavailable; serving isolated paths only: %m");
	} else if (bsdfilesystem_layout_provision(&st) == -1) {
		int pool_error;

		pool_error = errno;
		if (!bsdfilesystem_pool_missing_expected(pool_error)) {
			errno = pool_error;
			syslog(LOG_WARNING,
			    "pool %s unavailable; serving isolated paths only: %m",
			    st.cfg.pool);
		}
		if (st.persistent_fd != -1) {
			(void)close(st.persistent_fd);
			st.persistent_fd = -1;
		}
		if (st.ephemeral_fd != -1) {
			(void)close(st.ephemeral_fd);
			st.ephemeral_fd = -1;
		}
	} else {
		storage_available = true;
	}
	/* Raw acquisition authority has no role in request handling. */
	if (st.zfs_fd >= 0) {
		(void)close(st.zfs_fd);
		st.zfs_fd = -1;
	}
	st.storage_available = storage_available;
	/*
	 * The delivered /dev directory descriptor was only needed to openat("zfs")
	 * the control device (already closed above). Close the directory before forking
	 * the reaper and per-client workers so the sandboxed serving processes do
	 * not inherit a stray /dev directory fd they could openat(2) under.
	 */
	if (dev_dirfd >= 0)
		(void)close(dev_dirfd);

	/*
	 * The boot-scoped GC (reap_leases + reap_staging) and the reconcile
	 * reaper used to run HERE, before serving.  They are the slow part of a
	 * cold start (namespace walks over ZFS ioctls), and blocking on them
	 * before signalling provider-ready made the whole boot herd that waits
	 * on system.Filesystem time out (switchboard's on-demand 10s window),
	 * which in turn starved dependents like system.Log and system.Crypto.
	 * bsdfilesystem_serve() now runs them AFTER service_provider_ready()
	 * (waiters get their channel immediately) but BEFORE the accept loop
	 * dispatches any request -- so the "no connection served yet, every
	 * lease/clone is a prior-boot orphan" safety invariant still holds.
	 */
	setproctitle("-Filesystem");
	if (storage_available)
		syslog(LOG_NOTICE, "bsdfilesystem filesystem provider (pool %s)",
		    st.cfg.pool);
	else
		syslog(LOG_NOTICE,
		    "bsdfilesystem filesystem provider (isolated paths only)");

	/*
	 * Serve as a socket-free service_provider: expose system.Filesystem, enter
	 * capability mode, and dispatch each client on its own worker channel.
	 * bsdfilesystem_serve() owns the provider lifecycle and does not return on
	 * success.
	 */
	if (bsdfilesystem_serve(&st) == -1)
		errx(1, "storage provider failed");

	return (0);
}
#endif /* !BSDFILESYSTEM_TESTING */
