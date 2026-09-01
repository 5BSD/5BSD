/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) — the [TZFS] storage daemon.
 *
 * Owns the storage plane: the root-pool handle and the /Capabilities layout.
 * It mints rights-limited TrustedZFS handles on request and passes them back
 * over its clients' mac_capability channels.  tzfsd is a socket-free
 * service_provider: it exposes the well-known name system.Filesystem and serves
 * each client on its own worker channel, exactly like every other
 * capability-plane daemon.  All name-based setup happens up front; the provider
 * then cap_enter()s and serves every request from its retained capability
 * handles.
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

#include "tzfsd.h"

static void
usage(void)
{

	(void)fprintf(stderr, "usage: tzfsd [-c config]\n");
	exit(1);
}

/*
 * Guarantee fds 0/1/2 are open before any capability handle is created, so a
 * handle can never occupy a stdio slot.  tzfsd is launched by serviced without
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

int
main(int argc, char **argv)
{
	struct tzfsd_state st;
	const char *conf = TZFSD_DEFAULT_CONF;
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
	 * LOG_PERROR unconditionally: serviced captures the copies on the
	 * launching side; there is no controlling terminal in production.
	 */
	openlog("tzfsd", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	/* Before opening any capability handle (see reserve_stdio). */
	reserve_stdio();

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = -1;
	st.root_fd = -1;

	tzfsd_config_defaults(&st.cfg);
	if (tzfsd_config_load(&st.cfg, conf) == -1) {
		syslog(LOG_ERR, "config %s: %m", conf);
		return (1);
	}

	/* All name-based work happens before the provider enters capability mode. */
	if (tzfsd_ensure_zfs(&st.cfg) == -1)
		errx(1, "ZFS is required but not available");
	if (tzfsd_layout_provision(&st) == -1)
		errx(1, "layout provisioning failed (is pool %s imported?)",
		    st.cfg.pool);

	/*
	 * Boot-scoped GC of ephemeral leases orphaned by a prior boot.  Runs
	 * once here, before any connection is served, so it never races a live
	 * consumer's lease.  Non-fatal: a reap failure must not stop serving.
	 */
	if (tzfsd_reap_leases(&st) == -1)
		syslog(LOG_WARNING, "reap orphan leases: %m");

	/*
	 * Retain a root directory fd for TZFSD_OP_OPEN before entering capability
	 * mode.  In capability mode tzfsd can no longer open by absolute path, but
	 * openat(2) from this retained fd with a relative path is legal, so this
	 * is what lets it hand out isolated descriptors for existing paths.
	 */
	st.root_fd = open("/", O_DIRECTORY | O_CLOEXEC);
	if (st.root_fd == -1)
		errx(1, "cannot retain root directory fd");

	setproctitle("-Filesystem");
	syslog(LOG_NOTICE, "tzfsd filesystem provider (pool %s)", st.cfg.pool);

	/*
	 * Serve as a socket-free service_provider: expose system.Filesystem, enter
	 * capability mode, and dispatch each client on its own worker channel.
	 * tzfsd_serve() owns the provider lifecycle and does not return on
	 * success.
	 */
	if (tzfsd_serve(&st) == -1)
		errx(1, "storage provider failed");

	return (0);
}
