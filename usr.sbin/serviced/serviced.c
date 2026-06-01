/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced — service manager and naming registry.
 *
 * Started by oracled as its single child.  Inherits a cap_rt pair
 * on fd 3 for requesting tokens, pairs, and coalitions from the
 * oracle.  Reads service manifests, dependency-sorts, pdfork/execs
 * services, and manages their lifecycle (restart, shutdown).
 *
 * Startup sequence:
 *   1. Inherit pair fd from ORACLED_PAIR_FD env (fd 3)
 *   2. Create kqueue, register pair + signals
 *   3. Send ORACLE_OP_READY to oracled
 *   4. Load manifests from SERVICED_MANIFEST_DIR
 *   5. Dependency sort
 *   6. Fork/exec services (requesting tokens from oracled)
 *   7. Enter event loop
 */

#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <dev/cap_rt/cap_rt_capprotect_proto.h>
#include <dev/cap_rt/cap_rt_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "serviced.h"

struct serviced_state sd;
int serviced_kq;

static void
add_signal_event(int kq, int sig)
{
	struct kevent kev;

	EV_SET(&kev, sig, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_ERR, "kevent signal %d: %m", sig);
	(void)signal(sig, SIG_IGN);
}

static void
event_loop(void)
{
	struct kevent events[16];
	struct kevent *kev;
	int i, n;

	while (sd.running) {
		n = kevent(serviced_kq, NULL, 0, events, 16, NULL);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "kevent: %m");
			break;
		}

		for (i = 0; i < n; i++) {
			kev = &events[i];

			if (kev->filter == EVFILT_SIGNAL) {
				switch ((int)kev->ident) {
				case SIGTERM:
				case SIGINT:
					syslog(LOG_INFO,
					    "received signal %d, shutting down",
					    (int)kev->ident);
					sd.shutting_down = true;
					sd.running = false;
					supervisor_stop(serviced_kq);
					break;
				case SIGHUP:
					syslog(LOG_INFO,
					    "received SIGHUP, reloading");
					supervisor_reload(serviced_kq,
					    NULL, 0);
					break;
				case SIGCHLD:
					/* Reap strays. */
					while (waitpid(-1, NULL, WNOHANG) > 0)
						;
					break;
				}
				continue;
			}

			/* Control socket — accept new connections. */
			if (kev->filter == EVFILT_READ &&
			    sctl_fd() >= 0 &&
			    (int)kev->ident == sctl_fd()) {
				sctl_accept();
				continue;
			}

			/* Control socket — per-connection events. */
			if (sctl_is_conn_event(kev)) {
				sctl_conn_event(kev);
				continue;
			}

			if (kev->filter == EVFILT_READ &&
			    (int)kev->ident == sd.oracle_pair_fd) {
				if (kev->flags & EV_EOF) {
					syslog(LOG_CRIT,
					    "oracle died, stopping all services");
					sd.shutting_down = true;
					sd.running = false;
					supervisor_stop(serviced_kq);
				}
				continue;
			}

			/* Process descriptor events — service lifecycle. */
			if (kev->filter == EVFILT_PROCDESC) {
				supervisor_handle_procdesc(kev);
				continue;
			}

			/* Restart and stop-kill timers. */
			if (kev->filter == EVFILT_TIMER) {
				supervisor_handle_timer(kev);
				continue;
			}

			/* Service pair channel events. */
			if (kev->filter == EVFILT_READ &&
			    kev->udata != NULL) {
				supervisor_handle_pair(kev);
				continue;
			}
		}
	}
}

static void
usage(void)
{

	fprintf(stderr, "usage: serviced [-d manifest_dir]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct kevent kev;
	const char *pair_fd_str, *s, *manifest_dir_env;
	int ch;

	memset(&sd, 0, sizeof(sd));
	sd.oracle_pair_fd = -1;
	sd.pair_svc_fd = -1;
	sd.coalition_svc_fd = -1;
	sd.capprotect_fd = -1;

	openlog("serviced", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/* Parse arguments. */
	while ((ch = getopt(argc, argv, "d:")) != -1) {
		switch (ch) {
		case 'd':
			strlcpy(sd.manifest_dir, optarg,
			    sizeof(sd.manifest_dir));
			break;
		default:
			usage();
		}
	}

	/* Inherit pair fd. */
	pair_fd_str = getenv("ORACLED_PAIR_FD");
	if (pair_fd_str != NULL) {
		sd.oracle_pair_fd = (int)strtol(pair_fd_str, NULL, 10);
		if (sd.oracle_pair_fd < 0) {
			syslog(LOG_ERR, "invalid ORACLED_PAIR_FD: %s",
			    pair_fd_str);
			return (1);
		}
	} else {
		syslog(LOG_ERR, "ORACLED_PAIR_FD not set");
		return (1);
	}

	/* Non-blocking so oracle_rpc can timeout instead of hanging. */
	(void)fcntl(sd.oracle_pair_fd, F_SETFL, O_NONBLOCK);

	/* Inherit delegated service instance fds (optional). */
	s = getenv("SERVICED_PAIR_SVC_FD");
	if (s != NULL) {
		sd.pair_svc_fd = (int)strtol(s, NULL, 10);
		if (sd.pair_svc_fd < 0) sd.pair_svc_fd = -1;
	}
	s = getenv("SERVICED_COALITION_SVC_FD");
	if (s != NULL) {
		sd.coalition_svc_fd = (int)strtol(s, NULL, 10);
		if (sd.coalition_svc_fd < 0) sd.coalition_svc_fd = -1;
	}
	s = getenv("SERVICED_CAPPROTECT_FD");
	if (s != NULL) {
		sd.capprotect_fd = (int)strtol(s, NULL, 10);
		if (sd.capprotect_fd < 0) sd.capprotect_fd = -1;
	}
	if (sd.pair_svc_fd >= 0) {
		(void)fcntl(sd.pair_svc_fd, F_SETFL, O_NONBLOCK);
		syslog(LOG_INFO, "inherited service fds: pair=%d "
		    "coalition=%d capprotect=%d",
		    sd.pair_svc_fd, sd.coalition_svc_fd, sd.capprotect_fd);
	}
	if (sd.coalition_svc_fd >= 0)
		(void)fcntl(sd.coalition_svc_fd, F_SETFL, O_NONBLOCK);

	/* Manifest dir: CLI flag > env > default. */
	if (sd.manifest_dir[0] == '\0') {
		manifest_dir_env = getenv("SERVICED_MANIFEST_DIR");
		if (manifest_dir_env != NULL)
			strlcpy(sd.manifest_dir, manifest_dir_env,
			    sizeof(sd.manifest_dir));
		else
			strlcpy(sd.manifest_dir, "/etc/oracled.d",
			    sizeof(sd.manifest_dir));
	}

	/* Apply capprotect shield if available. */
	if (sd.capprotect_fd >= 0) {
		struct cap_rt_call_args call;
		struct cp_request cp_req;

		memset(&cp_req, 0, sizeof(cp_req));
		cp_req.op = CP_OP_SHIELD;
		/*
		 * Shield against external interference but NOT signals —
		 * oracled sends SIGHUP (reload) and SIGTERM (shutdown)
		 * via pdkill on our process descriptor.
		 * CP_SF_SIGNAL would block those.
		 */
		cp_req.flags = CP_SF_PTRACE | CP_SF_WAIT | CP_SF_SCHED |
		    CP_SF_KTRACE;

		memset(&call, 0, sizeof(call));
		call.req = &cp_req;
		call.req_len = sizeof(cp_req);

		if (ioctl(sd.capprotect_fd, CAP_RT_CALL, &call) == -1)
			syslog(LOG_WARNING, "capprotect shield: %m");
		else
			syslog(LOG_INFO, "capprotect shield active");
		close(sd.capprotect_fd);
		sd.capprotect_fd = -1;
	}

	/* Create kqueue. */
	serviced_kq = kqueue();
	if (serviced_kq == -1) {
		syslog(LOG_ERR, "kqueue: %m");
		return (1);
	}

	/* Register oracle pair for read (detect EOF = oracle died). */
	EV_SET(&kev, sd.oracle_pair_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "kevent pair: %m");
		return (1);
	}

	/* Set up control socket. */
	if (sctl_setup() == 0) {
		EV_SET(&kev, sctl_fd(), EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1)
			syslog(LOG_WARNING, "kevent sctl: %m");
	}

	/* Register signals. */
	add_signal_event(serviced_kq, SIGTERM);
	add_signal_event(serviced_kq, SIGINT);
	add_signal_event(serviced_kq, SIGHUP);
	add_signal_event(serviced_kq, SIGCHLD);

	/* Tell oracled we're ready. */
	if (oracle_send_ready(sd.oracle_pair_fd) != 0)
		syslog(LOG_WARNING, "failed to send READY to oracled");

	sd.running = true;
	syslog(LOG_INFO, "serviced started, manifest_dir=%s",
	    sd.manifest_dir);

	/* Load manifests, dependency sort, launch services. */
	if (supervisor_start(serviced_kq) != 0)
		syslog(LOG_WARNING, "supervisor_start failed");

	event_loop();

	/* Graceful shutdown: stop all services. */
	supervisor_stop(serviced_kq);
	{
		struct kevent sevents[8];
		int w, si, sn;

		w = 0;
		while (!supervisor_is_stopped() && w < 600) {  /* 60 seconds */
			sn = kevent(serviced_kq, NULL, 0, sevents, 8,
			    &(struct timespec){.tv_sec = 0, .tv_nsec = 100000000});
			if (sn > 0) {
				for (si = 0; si < sn; si++) {
					if (sevents[si].filter == EVFILT_PROCDESC)
						supervisor_handle_procdesc(&sevents[si]);
					else if (sevents[si].filter == EVFILT_TIMER)
						supervisor_handle_timer(&sevents[si]);
				}
			}
			w++;
		}
	}
	supervisor_teardown_state();
	sctl_teardown();

	syslog(LOG_INFO, "serviced exiting");
	close(serviced_kq);
	return (0);
}
