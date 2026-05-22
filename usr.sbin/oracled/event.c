/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/event.h>

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

static void
shutdown_and_exit(int sig)
{
	syslog(LOG_INFO, "stopping on signal %d", sig);
	if (!test_mode)
		kill_subtree();
	reap_children();
	if (cap_rt_fd >= 0)
		close(cap_rt_fd);
	pidfile_remove(pidfh);
	closelog();
	running = false;
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

	while (running) {
		nev = kevent(kq, NULL, 0, &kev, 1, NULL);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent wait");
		}
		if (nev == 0)
			continue;

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
