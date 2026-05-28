/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oracled — Oracle capability-world service manager.
 *
 * Startup lifecycle:
 *   1. Parse arguments, open syslog, acquire pidfile
 *   2. Daemonize (unless foreground mode)
 *   3. Harden process (procctl self-policy)
 *   4. Initialize cap_rt (open device, isolate, shield)
 *   5. Create control socket
 *   6. Enter event loop
 *
 * Shutdown lifecycle (see event.c):
 *   1. Kill process subtree
 *   2. Reap children
 *   3. Close control socket
 *   4. Release cap_rt services (shield, isolation, device)
 *   5. Remove pidfile
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"

#define	ORACLED_PIDFILE	"/var/run/oracled.pid"

struct pidfh	*pidfh;
bool		 foreground;
bool		 test_mode;
bool		 running = true;
int		 control_fd = -1;

static void
usage(void)
{

	fprintf(stderr, "usage: oracled [-dT] [-p pidfile]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *pidfile;
	pid_t otherpid;
	int ch;

	pidfile = ORACLED_PIDFILE;
	while ((ch = getopt(argc, argv, "dTp:")) != -1) {
		switch (ch) {
		case 'd':
			foreground = true;
			break;
		case 'T':
			foreground = true;
			test_mode = true;
			break;
		case 'p':
			pidfile = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	/* Phase 1: logging and pidfile. */
	openlog("oracled", LOG_PID | (foreground ? LOG_PERROR : 0),
	    LOG_DAEMON);

	if (!test_mode && getuid() != 0)
		errx(1, "must run as root");

	pidfh = pidfile_open(pidfile, 0600, &otherpid);
	if (pidfh == NULL) {
		if (errno == EEXIST)
			errx(1, "already running, pid %jd",
			    (intmax_t)otherpid);
		err(1, "cannot open pidfile %s", pidfile);
	}

	/* Phase 2: daemonize. */
	if (!foreground && daemon(0, 0) == -1) {
		pidfile_remove(pidfh);
		err(1, "daemon");
	}
	if (pidfile_write(pidfh) == -1) {
		pidfile_remove(pidfh);
		err(1, "pidfile_write");
	}

	/* Phase 3: harden process. */
	if (!test_mode)
		apply_procctl_self_policy();
	else
		syslog(LOG_INFO, "test mode: skipping procctl");

	/* Phase 4: capability runtime. */
	if (!test_mode)
		cap_rt_setup();
	else
		syslog(LOG_INFO, "test mode: skipping cap_rt");

	/* Phase 5: control socket. */
	if (!test_mode) {
		control_fd = setup_control_socket();
		if (control_fd == -1)
			syslog(LOG_WARNING, "failed to create control socket");
	} else {
		syslog(LOG_INFO, "test mode: skipping control socket");
	}

	/* Phase 6: event loop. */
	syslog(LOG_INFO, "started");
	event_loop();
}
