/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"

#define	ORACLED_PIDFILE	"/var/run/oracled.pid"

struct pidfh	*pidfh;
int		 cap_rt_fd = -1;
bool		 foreground;
bool		 test_mode;
bool		 running = true;

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

	openlog("oracled", LOG_PID | (foreground ? LOG_PERROR : 0),
	    LOG_DAEMON);

	if (!test_mode && getuid() != 0)
		errx(1, "must run as root");

	pidfh = pidfile_open(pidfile, 0600, &otherpid);
	if (pidfh == NULL) {
		if (errno == EEXIST)
			errx(1, "already running, pid %jd", (intmax_t)otherpid);
		err(1, "cannot open pidfile %s", pidfile);
	}

	if (!foreground && daemon(0, 0) == -1) {
		pidfile_remove(pidfh);
		err(1, "daemon");
	}

	if (pidfile_write(pidfh) == -1) {
		pidfile_remove(pidfh);
		err(1, "pidfile_write");
	}

	if (!test_mode)
		apply_procctl_self_policy();
	else
		syslog(LOG_INFO, "test mode: skipping procctl self-policy");

	if (!test_mode) {
		cap_rt_fd = open("/dev/cap_rt", O_RDWR | O_CLOEXEC);
		if (cap_rt_fd == -1)
			syslog(LOG_WARNING, "open /dev/cap_rt failed: %m");
		else
			syslog(LOG_INFO, "opened /dev/cap_rt control device");
	} else {
		syslog(LOG_INFO, "test mode: skipping /dev/cap_rt open");
	}

	syslog(LOG_INFO, "started");
	event_loop();
}
