/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Main event loop and shutdown sequencing.
 *
 * Uses kqueue(2) to multiplex signals, the control socket, and
 * bootstrap lifecycle events (serviced process descriptor and
 * pair channel protocol).  Shutdown reverses the startup lifecycle
 * (see oracled.c).
 *
 * The daemon is strictly single-threaded.  Reload (SIGHUP or
 * CTL_OP_RELOAD) updates authority claims only — service management
 * is handled by serviced.
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
#include "commands.h"
#include "probes.h"

int event_kq = -1;

#define	SHUTDOWN_TIMER_IDENT	99999

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
	bootstrap_stop();

	{
		struct kevent kev;
		EV_SET(&kev, SHUTDOWN_TIMER_IDENT, EVFILT_TIMER,
		    EV_ADD | EV_ONESHOT, NOTE_SECONDS, 30, NULL);
		if (kevent(event_kq, &kev, 1, NULL, 0, NULL) == -1)
			syslog(LOG_WARNING, "shutdown watchdog timer: %m");
	}
}

static void
shutdown_finish(void)
{

	if (!od.shutting_down)
		return;
	od.shutting_down = false;

	{
		struct kevent kev;
		EV_SET(&kev, SHUTDOWN_TIMER_IDENT, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(event_kq, &kev, 1, NULL, 0, NULL);
	}

	if (!od.test_mode)
		kill_subtree();
	reap_children();
	ctl_teardown();
	cap_rt_teardown();
	pidfile_remove(od.pidfh);

	if (pending_reboot) {
		reboot(pending_reboot_howto);
		syslog(LOG_CRIT, "reboot(2) failed: %m");
		_exit(1);
	}

	closelog();
	od.running = false;
}

static void
handle_action(int action, int howto)
{

	if (action & CTL_ACTION_REBOOT) {
		syslog(LOG_INFO, "rebooting via control socket");
		pending_reboot = true;
		pending_reboot_howto = howto;
		shutdown_begin(0);
	} else if (action & CTL_ACTION_SHUTDOWN) {
		shutdown_begin(0);
	}
}

/*
 * SIGHUP reload: re-read config, update authority claims.
 * Service manifest reload is handled by serviced.
 */
static void
sighup_reload(void)
{
	struct oracled_config newcfg;

	syslog(LOG_INFO, "reload requested (SIGHUP)");
	config_init_defaults(&newcfg);
	if (config_load(&newcfg, od.conffile) == 0) {
		if (!od.test_mode)
			cap_rt_reload_claims(&newcfg);
		config_apply_claims(&newcfg);
	} else {
		syslog(LOG_WARNING,
		    "reload: config parse error, keeping existing");
	}

	/* Forward SIGHUP to serviced so it reloads manifests. */
	bootstrap_signal(SIGHUP);
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

	/*
	 * Ignore SIGPIPE — nonblocking write() on a closed client
	 * socket must return EPIPE, not kill the daemon.
	 */
	signal(SIGPIPE, SIG_IGN);

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

	/* Start serviced as our single child. */
	bootstrap_start(kq);

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

		/* Listening socket — accept new connections. */
		if (kev.filter == EVFILT_READ &&
		    (int)kev.ident == cfd && kev.udata == NULL) {
			if (!od.shutting_down)
				(void)ctl_accept();
			if (od.shutting_down && bootstrap_is_stopped())
				shutdown_finish();
			continue;
		}

		/* Client connection events. */
		if (ctl_is_conn_event(&kev)) {
			int action, howto;

			howto = 0;
			action = ctl_conn_event(&kev, &howto);
			if (action != CTL_ACTION_NONE)
				handle_action(action, howto);
			if (od.shutting_down && bootstrap_is_stopped())
				shutdown_finish();
			continue;
		}

		/* Bootstrap: serviced process descriptor. */
		if (bootstrap_is_procdesc(&kev)) {
			bootstrap_handle_exit(&kev, kq);
			if (od.shutting_down && bootstrap_is_stopped())
				shutdown_finish();
			continue;
		}

		/* Bootstrap: pair channel protocol from serviced. */
		if (bootstrap_is_pair(&kev)) {
			if (kev.flags & EV_EOF) {
				syslog(LOG_WARNING,
				    "serviced pair closed unexpectedly");
			} else {
				oracle_proto_dispatch(&kev);
			}
			continue;
		}

		/* Bootstrap: restart timer for serviced. */
		if (bootstrap_is_timer(&kev)) {
			bootstrap_handle_timer(&kev, kq);
			continue;
		}

		/* Shutdown watchdog timer. */
		if (kev.filter == EVFILT_TIMER && kev.udata == NULL &&
		    kev.ident == SHUTDOWN_TIMER_IDENT) {
			syslog(LOG_WARNING,
			    "shutdown timed out after 30 seconds");
			shutdown_finish();
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
			if (!od.shutting_down)
				sighup_reload();
			break;
		case SIGTERM:
		case SIGINT:
			shutdown_begin((int)kev.ident);
			break;
		default:
			break;
		}
		if (od.shutting_down && bootstrap_is_stopped())
			shutdown_finish();
	}

	(void)close(kq);
	event_kq = -1;
}
