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

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"

static void
add_signal_event(int kq, int sig)
{
	struct kevent kev;

	signal(sig, SIG_IGN);
	EV_SET(&kev, sig, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		err(1, "kevent signal %d", sig);
}

/*
 * Graceful shutdown.  reason > 0 is a signal number, 0 means
 * the control socket requested it.
 */
static void
shutdown_and_exit(int reason)
{

	if (reason > 0)
		syslog(LOG_INFO, "stopping on signal %d", reason);
	else
		syslog(LOG_INFO, "stopping via control socket");

	if (!od.test_mode)
		kill_subtree();
	reap_children();
	teardown_control_socket();
	cap_rt_teardown();
	pidfile_remove(od.pidfh);
	closelog();
	od.running = false;
}

void
event_loop(void)
{
	struct kevent kev;
	int kq, nev;

	kq = kqueue();
	if (kq == -1)
		err(1, "kqueue");

	add_signal_event(kq, SIGCHLD);
	add_signal_event(kq, SIGHUP);
	add_signal_event(kq, SIGTERM);
	add_signal_event(kq, SIGINT);

	if (od.control_fd >= 0) {
		EV_SET(&kev, od.control_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
			err(1, "kevent control socket");
	}

	while (od.running) {
		nev = kevent(kq, NULL, 0, &kev, 1, NULL);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent wait");
		}
		if (nev == 0)
			continue;

		if (kev.filter == EVFILT_READ &&
		    (int)kev.ident == od.control_fd) {
			int action;

			action = handle_control_connection();
			if (action & CTL_ACTION_REBOOT) {
				shutdown_and_exit(0);
				reboot(od.reboot_howto);
			}
			if (action & CTL_ACTION_SHUTDOWN)
				shutdown_and_exit(0);
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
			break;
		default:
			break;
		}
	}

	(void)close(kq);
}
