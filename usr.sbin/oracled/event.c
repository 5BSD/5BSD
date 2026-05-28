/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Main event loop and shutdown sequencing.
 *
 * Uses kqueue(2) to multiplex signals and the control socket.
 * Shutdown reverses the startup lifecycle (see oracled.c).
 */

#include <sys/event.h>
#include <sys/reboot.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "probes.h"

static void
add_signal_event(int kq, int sig)
{
	struct kevent kev;

	signal(sig, SIG_IGN);
	EV_SET(&kev, sig, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_CRIT, "kevent signal %d: %m", sig);
		exit(1);
	}
}

static void
shutdown_and_exit(int reason)
{

	ORACLED_PROBE_SHUTDOWN(reason);
	if (reason > 0)
		syslog(LOG_INFO, "stopping on signal %d", reason);
	else
		syslog(LOG_INFO, "stopping via control socket");

	if (!od.test_mode)
		kill_subtree();
	reap_children();
	ctl_teardown();
	cap_rt_teardown();
	pidfile_remove(od.pidfh);
	closelog();
	od.running = false;
}

void
event_loop(void)
{
	struct kevent kev;
	int cfd, kq, nev;

	kq = kqueue();
	if (kq == -1) {
		syslog(LOG_CRIT, "kqueue: %m");
		exit(1);
	}

	add_signal_event(kq, SIGCHLD);
	add_signal_event(kq, SIGHUP);
	add_signal_event(kq, SIGTERM);
	add_signal_event(kq, SIGINT);

	cfd = ctl_fd();
	if (cfd >= 0) {
		EV_SET(&kev, cfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
			syslog(LOG_CRIT, "kevent control socket: %m");
			exit(1);
		}
	}

	while (od.running) {
		nev = kevent(kq, NULL, 0, &kev, 1, NULL);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_CRIT, "kevent wait: %m");
			exit(1);
		}
		if (nev == 0)
			continue;

		if (kev.filter == EVFILT_READ &&
		    (int)kev.ident == cfd) {
			int action, howto;

			howto = 0;
			action = ctl_handle(&howto);
			if (action & CTL_ACTION_REBOOT) {
				syslog(LOG_INFO,
				    "stopping via control socket");
				reboot(howto);
				/* reboot(2) should not return. */
				syslog(LOG_CRIT, "reboot(2) failed: %m");
				_exit(1);
			} else if (action & CTL_ACTION_SHUTDOWN) {
				shutdown_and_exit(0);
				break;	/* exit loop immediately */
			}
			continue;
		}

		if (kev.filter != EVFILT_SIGNAL)
			continue;

		switch ((int)kev.ident) {
		case SIGCHLD:
			reap_children();
			break;
		case SIGHUP:
			syslog(LOG_INFO, "reload requested");
			break;
		case SIGTERM:
		case SIGINT:
			shutdown_and_exit((int)kev.ident);
			break;	/* od.running is false, loop exits */
		default:
			break;
		}
	}

	(void)close(kq);
}
