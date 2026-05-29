/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Main event loop and shutdown sequencing.
 *
 * Uses kqueue(2) to multiplex signals, the control socket, and
 * service lifecycle events (process descriptors, pair channels,
 * restart timers).  Shutdown reverses the startup lifecycle
 * (see oracled.c).
 */

#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/reboot.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "probes.h"

int event_kq = -1;

static bool pending_reboot;
static int pending_reboot_howto;

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
shutdown_begin(int reason)
{

	if (od.shutting_down)
		return;

	ORACLED_PROBE_SHUTDOWN(reason);
	if (reason > 0)
		syslog(LOG_INFO, "stopping on signal %d", reason);
	else
		syslog(LOG_INFO, "stopping via control socket");

	od.shutting_down = true;
	supervisor_stop(event_kq);
}

static void
shutdown_finish(void)
{

	if (!od.test_mode)
		kill_subtree();
	reap_children();
	ctl_teardown();
	cap_rt_teardown();
	pidfile_remove(od.pidfh);
	supervisor_teardown_state();

	if (pending_reboot) {
		reboot(pending_reboot_howto);
		/* reboot(2) should not return. */
		syslog(LOG_CRIT, "reboot(2) failed: %m");
		_exit(1);
	}

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
	event_kq = kq;

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

	/* Load manifests and launch agents. */
	supervisor_start(kq);

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

		/* Control socket — identified by fd and NULL udata. */
		if (kev.filter == EVFILT_READ &&
		    (int)kev.ident == cfd && kev.udata == NULL) {
			int action, howto;

			if (od.shutting_down)
				continue;
			howto = 0;
			action = ctl_handle(&howto);
			if (action & CTL_ACTION_REBOOT) {
				syslog(LOG_INFO,
				    "rebooting via control socket");
				pending_reboot = true;
				pending_reboot_howto = howto;
				shutdown_begin(0);
			} else if (action & CTL_ACTION_SHUTDOWN) {
				shutdown_begin(0);
			}
			if (od.shutting_down && supervisor_is_stopped())
				shutdown_finish();
			continue;
		}

		/* Process descriptor events (service lifecycle). */
		if (kev.filter == EVFILT_PROCDESC) {
			supervisor_handle_procdesc(&kev);
			if (od.shutting_down && supervisor_is_stopped())
				shutdown_finish();
			continue;
		}

		/* Restart timer fired. */
		if (kev.filter == EVFILT_TIMER && kev.udata != NULL) {
			supervisor_handle_timer(&kev);
			if (od.shutting_down && supervisor_is_stopped())
				shutdown_finish();
			continue;
		}

		/* Pair channel events (service communication). */
		if (kev.filter == EVFILT_READ && kev.udata != NULL) {
			supervisor_handle_pair(&kev);
			continue;
		}

		/* Signal events. */
		if (kev.filter != EVFILT_SIGNAL)
			continue;

		switch ((int)kev.ident) {
		case SIGCHLD:
			reap_children();
			break;
		case SIGHUP:
			if (!od.shutting_down) {
				syslog(LOG_INFO, "reload requested (SIGHUP)");
				supervisor_reload(kq, NULL, 0);
			}
			break;
		case SIGTERM:
		case SIGINT:
			shutdown_begin((int)kev.ident);
			break;	/* od.running is false, loop exits */
		default:
			break;
		}
		if (od.shutting_down && supervisor_is_stopped())
			shutdown_finish();
	}

	(void)close(kq);
	event_kq = -1;
}
