/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oracled — Oracle capability-world service manager.
 *
 * Startup lifecycle:
 *   1. Parse arguments, load config, open syslog, acquire pidfile
 *   2. Daemonize (unless foreground mode)
 *   3. Harden process (procctl self-policy)
 *   4. Initialize cap_rt (open device, claim resources, integrity)
 *   5. Create control socket
 *   6. Enter event loop
 *      6a. Load manifests, sort dependencies, launch services
 *      6b. Main kevent loop (control + signals + procdesc + pairs)
 *
 * Shutdown lifecycle (see event.c):
 *   1. Stop services (graceful, then forceful via coalition)
 *   2. Kill process subtree (backstop)
 *   3. Reap children
 *   4. Close control socket
 *   5. Release cap_rt services (integrity, claims, device)
 *   6. Remove pidfile
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "probes.h"

struct oracled_state od;

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: oracled [-dT] [-f conffile] [-p pidfile]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *conffile, *pidfile_override;
	pid_t otherpid;
	int ch;

	conffile = ORACLED_DEFAULT_CONFFILE;
	pidfile_override = NULL;

	while ((ch = getopt(argc, argv, "dTf:p:")) != -1) {
		switch (ch) {
		case 'd':
			od.foreground = true;
			break;
		case 'T':
			od.foreground = true;
			od.test_mode = true;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'p':
			pidfile_override = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	/*
	 * Phase 1: config, logging, pidfile.
	 *
	 * Load config before syslog so parse errors go to stderr.
	 * CLI flags override config values after loading.
	 */
	config_init_defaults(&od.cfg);
	if (config_load(&od.cfg, conffile) != 0)
		errx(1, "configuration error");
	strlcpy(od.conffile, conffile, sizeof(od.conffile));
	ORACLED_PROBE_CONFIG(conffile);

	/* CLI -p overrides config pidfile. */
	if (pidfile_override != NULL)
		strlcpy(od.cfg.pidfile, pidfile_override,
		    sizeof(od.cfg.pidfile));

	openlog("oracled", LOG_PID | (od.foreground ? LOG_PERROR : 0),
	    LOG_DAEMON);

	if (!od.test_mode && getuid() != 0)
		errx(1, "must run as root");

	od.pidfh = pidfile_open(od.cfg.pidfile, 0600, &otherpid);
	if (od.pidfh == NULL) {
		if (errno == EEXIST)
			errx(1, "already running, pid %jd",
			    (intmax_t)otherpid);
		err(1, "cannot open pidfile %s", od.cfg.pidfile);
	}

	/* Phase 2: daemonize.
	 * After daemon(), stderr is closed — use syslog for errors. */
	if (!od.foreground && daemon(0, 0) == -1) {
		pidfile_remove(od.pidfh);
		err(1, "daemon");
	}
	if (pidfile_write(od.pidfh) == -1) {
		pidfile_remove(od.pidfh);
		syslog(LOG_CRIT, "pidfile_write: %m");
		exit(1);
	}

	/* Log config after daemon() so PID matches the pidfile. */
	config_log(&od.cfg);

	/* Phase 3: harden process. */
	if (!od.test_mode) {
		if (apply_procctl_self_policy() == -1) {
			syslog(LOG_ERR,
			    "failed to apply process hardening policy");
			return (1);
		}
	} else
		syslog(LOG_INFO, "test mode: skipping procctl");

	/* Phase 4: capability runtime. */
	if (!od.test_mode) {
		if (cap_rt_setup() == -1) {
			syslog(LOG_ERR,
			    "cap_rt not available, cannot start");
			exit(1);
		}
	} else
		syslog(LOG_INFO, "test mode: skipping cap_rt");

	/* Phase 5: control socket. */
	if (!od.test_mode) {
		if (ctl_setup() == -1) {
			syslog(LOG_ERR,
			    "failed to create control socket, cannot start");
			exit(1);
		}
	} else {
		syslog(LOG_INFO, "test mode: skipping control socket");
	}

	/* Phase 6: event loop. */
	od.running = true;
	syslog(LOG_INFO, "started");
	ORACLED_PROBE_STARTUP();
	event_loop();
	exit(0);
}
