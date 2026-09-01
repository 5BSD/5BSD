/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) — the [TZFS] storage daemon.
 *
 * Owns the storage plane: the root-pool handle and the /Capabilities layout.
 * It mints rights-limited TrustedZFS handles on request and passes them back
 * over SCM_RIGHTS.  All name-based setup happens
 * up front; the daemon then cap_enter()s and serves every request from its
 * retained capability handles.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

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

static int
open_listener(void)
{
	struct sockaddr_un sun;
	int fd;

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		syslog(LOG_ERR, "socket: %m");
		return (-1);
	}
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	(void)strlcpy(sun.sun_path, TZFSD_SOCK_PATH, sizeof(sun.sun_path));
	(void)unlink(TZFSD_SOCK_PATH);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		syslog(LOG_ERR, "bind %s: %m", TZFSD_SOCK_PATH);
		(void)close(fd);
		return (-1);
	}
	/* Root-only: peers are authorityd/serviced/tzfsctl, or passed channels. */
	(void)chmod(TZFSD_SOCK_PATH, 0600);
	if (listen(fd, 64) == -1) {
		syslog(LOG_ERR, "listen: %m");
		(void)close(fd);
		return (-1);
	}
	return (fd);
}

static void
write_ready(void)
{
	int fd;

	fd = open(TZFSD_READY_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	    0644);
	if (fd != -1)
		(void)close(fd);
}

static int
enter_capability_mode(void)
{

	if (cap_enter() == -1)
		return (-1);
	return (0);
}

static void
usage(void)
{

	(void)fprintf(stderr, "usage: tzfsd [-f] [-c config]\n");
	exit(1);
}

/*
 * Guarantee fds 0/1/2 are open before any capability handle is created, so a
 * handle can never occupy a stdio slot.  tzfsd is launched by authorityd without
 * a controlling terminal, and daemon(3) later redirects 0/1/2 to /dev/null: a
 * capability handle that landed on fd 0/1/2 would be silently replaced by
 * /dev/null, and every subsequent ZFD_OPENAT/ZFD_* on it would fail ENOTTY —
 * breaking every storage request while start-up provisioning (done before
 * daemon(3)) still appeared to work.
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
	bool foreground = false;
	int ch;

	while ((ch = getopt(argc, argv, "c:f")) != -1) {
		switch (ch) {
		case 'c':
			conf = optarg;
			break;
		case 'f':
			foreground = true;
			break;
		default:
			usage();
		}
	}

	/*
	 * When serviced launches tzfsd as a supervised unit (P4a,
	 * docs/capability-authority-model.md) it exports CAPABILITY_UNIT_DIR
	 * (SERVICE_UNIT_DIR_ENV).  A serviced-managed daemon must NOT detach:
	 * serviced owns the process lifecycle through the process descriptor and
	 * takes readiness from cap_enter() (NOTE_CAPMODE), so a daemon(3) that
	 * reparents would make serviced see the launcher exit.  Stay foreground.
	 */
	if (getenv("CAPABILITY_UNIT_DIR") != NULL)
		foreground = true;

	/*
	 * LOG_PERROR unconditionally: before daemon(3) the copies land on the
	 * launching terminal (test harnesses capture them); after daemon(3)
	 * stderr is /dev/null, so production logging is unaffected.
	 */
	openlog("tzfsd", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	/* Before opening any capability handle (see reserve_stdio). */
	reserve_stdio();

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = -1;
	st.listen_fd = -1;

	tzfsd_config_defaults(&st.cfg);
	if (tzfsd_config_load(&st.cfg, conf) == -1) {
		syslog(LOG_ERR, "config %s: %m", conf);
		return (1);
	}

	/* All name-based work happens before cap_enter(). */
	if (tzfsd_ensure_zfs(&st.cfg) == -1)
		errx(1, "ZFS is required but not available");
	if (tzfsd_layout_provision(&st) == -1)
		errx(1, "layout provisioning failed (is pool %s imported?)",
		    st.cfg.pool);

	st.listen_fd = open_listener();
	if (st.listen_fd == -1)
		errx(1, "cannot open %s", TZFSD_SOCK_PATH);

	if (!foreground && daemon(0, 0) == -1)
		err(1, "daemon");

	setproctitle("-Storage");
	write_ready();
	syslog(LOG_NOTICE, "tzfsd ready on %s (pool %s)", TZFSD_SOCK_PATH,
	    st.cfg.pool);

	if (enter_capability_mode() == -1) {
		(void)unlink(TZFSD_READY_PATH);
		err(1, "cap_enter");
	}
	tzfsd_serve(&st);

	return (0);
}
