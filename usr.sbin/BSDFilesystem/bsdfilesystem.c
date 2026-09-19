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
 * capability-plane daemon.  All name-based setup happens up front; the provider
 * then enters AMBIENT authority -- it runs OUTSIDE capability mode, because ZFS
 * and mount(2) need the global namespace that capmode strips -- and serves every
 * request from its retained root/container handles.  Containment is therefore
 * NOT capsicum: it is the per-container scoping stamped on each channel plus
 * openat(2) relative to the retained root fd with O_RESOLVE_BENEATH/O_NOFOLLOW.
 */

#include <sys/types.h>

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
	const char *conf = BSDFILESYSTEM_DEFAULT_CONF;
	bool storage_available;
	int ch;

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

	bsdfilesystem_config_defaults(&st.cfg);
	if (bsdfilesystem_config_load(&st.cfg, conf) == -1) {
		syslog(LOG_ERR, "config %s: %m", conf);
		return (1);
	}

	/*
	 * All name-based work happens during startup; bsdfilesystem is ambient and never
	 * enters capability mode (ZFS/mount need the global namespace).
	 * Storage is unavailable on read-only installer media because there is no
	 * root pool yet.  Keep serving the independently useful, policy-gated
	 * isolated-open operation in that case; dataset operations already fail
	 * closed with ENXIO when their retained parents are absent.
	 */
	storage_available = false;
	if (bsdfilesystem_ensure_zfs(&st.cfg) == -1) {
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

	/*
	 * Boot-scoped GC of ephemeral leases orphaned by a prior boot.  Runs
	 * once here, before any connection is served, so it never races a live
	 * consumer's lease.  Non-fatal: a reap failure must not stop serving.
	 */
	if (storage_available && bsdfilesystem_reap_leases(&st) == -1)
		syslog(LOG_WARNING, "reap orphan leases: %m");

	/*
	 * Start the persistent-namespace reconcile child (container-model
	 * cleanup).  Forked here, before capability mode, so it inherits the
	 * retained persistent handle and can read switchboard's live directory by
	 * path.  It reaps a per-owner namespace only once its owner is no longer
	 * installed, and only against switchboard's published, ready live set, so
	 * it never races a live consumer.
	 */
	if (storage_available)
		bsdfilesystem_start_reaper(&st);

	/*
	 * Retain a root directory fd for BSDFILESYSTEM_OP_OPEN before entering capability
	 * mode.  In capability mode bsdfilesystem can no longer open by absolute path, but
	 * openat(2) from this retained fd with a relative path is legal, so this
	 * is what lets it hand out isolated descriptors for existing paths.
	 */
	st.root_fd = open("/", O_DIRECTORY | O_CLOEXEC);
	if (st.root_fd == -1)
		errx(1, "cannot retain root directory fd");

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
