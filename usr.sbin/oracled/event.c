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

	supervisor_stop(event_kq);

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

			howto = 0;
			action = ctl_handle(&howto);
			if (action & CTL_ACTION_REBOOT) {
				syslog(LOG_INFO,
				    "rebooting via control socket");
				supervisor_stop(kq);
				kill_subtree();
				reap_children();
				ctl_teardown();
				cap_rt_teardown();
				pidfile_remove(od.pidfh);
				reboot(howto);
				/* reboot(2) should not return. */
				syslog(LOG_CRIT, "reboot(2) failed: %m");
				_exit(1);
			} else if (action & CTL_ACTION_SHUTDOWN) {
				shutdown_and_exit(0);
				break;	/* exit loop immediately */
			} else if (action & CTL_ACTION_RELOAD) {
				supervisor_reload(kq);
			}
			continue;
		}

		/* Process descriptor events (service lifecycle). */
		if (kev.filter == EVFILT_PROCDESC) {
			supervisor_handle_procdesc(&kev);
			continue;
		}

		/* Restart timer fired. */
		if (kev.filter == EVFILT_TIMER && kev.udata != NULL) {
			struct svc_runtime *svc = kev.udata;
			svc->restart_pending = false;
			syslog(LOG_INFO, "service %s: restart timer fired",
			    svc->manifest.label);
			svc_exec(svc, kq);
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
			syslog(LOG_INFO, "reload requested (SIGHUP)");
			supervisor_reload(kq);
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
	event_kq = -1;
}
