/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Main event loop and shutdown sequencing.
 *
 * Uses kqueue(2) to multiplex signals, the control socket, and
 * bootstrap lifecycle events (serviced process descriptor and
 * channel protocol).  Shutdown reverses the startup lifecycle
 * (see authorityd.c).
 *
 * The daemon is strictly single-threaded.  Reload (SIGHUP or
 * CTL_OP_RELOAD) updates authority claims only — service management
 * is handled by serviced.
 */

#include <sys/capsicum.h>
#include <sys/event.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "authorityd.h"
#include "commands.h"
#include "probes.h"

int event_kq = -1;

#define	SHUTDOWN_TIMER_IDENT	99999

static struct timespec shutdown_start_ts;

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

	AUTHORITYD_PROBE_SHUTDOWN(reason);
	if (reason > 0)
		syslog(LOG_INFO, "stopping on signal %d", reason);
	else
		syslog(LOG_INFO, "stopping via control socket");

	od.shutting_down = true;
	clock_gettime(CLOCK_MONOTONIC, &shutdown_start_ts);
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
	mac_capability_teardown();
	pidfile_remove(od.pidfh);

	{
		struct timespec now;
		uint64_t dur;

		clock_gettime(CLOCK_MONOTONIC, &now);
		dur = (uint64_t)(now.tv_sec - shutdown_start_ts.tv_sec) *
		    1000000000ULL +
		    (uint64_t)(now.tv_nsec - shutdown_start_ts.tv_nsec);
		AUTHORITYD_PROBE_SHUTDOWN_DONE(dur);
	}
	closelog();
	od.running = false;
}

static void
handle_action(int action)
{

	if (action & CTL_ACTION_SHUTDOWN)
		shutdown_begin(0);
}

/*
 * SIGHUP reload: re-read config, update authority claims.
 * Service manifest reload is handled by serviced.
 */
static void
sighup_reload(void)
{
	struct authorityd_config newcfg;

	syslog(LOG_INFO, "reload requested (SIGHUP)");
	AUTHORITYD_PROBE_RELOAD();
	config_init_defaults(&newcfg);
	if (config_load(&newcfg, od.conffile) == 0) {
		if (!od.test_mode)
			mac_capability_reload_claims(&newcfg);
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
	if (cap_xfer_limit(kq, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(kq, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(kq, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_CRIT, "kqueue confinement: %m");
		close(kq);
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

	/* Start serviced as our single child (requires mac_capability). */
	if (!od.test_mode) {
		if (bootstrap_start(kq) == -1)
			syslog(LOG_ERR, "bootstrap: initial start failed, "
			    "running without service manager");
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
			int action;

			action = ctl_conn_event(&kev);
			if (action != CTL_ACTION_NONE)
				handle_action(action);
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

		/* Bootstrap: channel protocol from serviced. */
		if (bootstrap_is_channel(&kev)) {
			if (kev.flags & EV_EOF) {
				syslog(LOG_INFO,
				    "serviced closed channel");
				bootstrap_handle_channel_eof();
			} else {
				authority_proto_dispatch();
			}
			continue;
		}

		/* Bootstrap: restart timer for serviced. */
		if (bootstrap_is_timer(&kev)) {
			bootstrap_handle_timer(kq);
			continue;
		}

		/* Shutdown watchdog timer. */
		if (kev.filter == EVFILT_TIMER && kev.udata == NULL &&
		    kev.ident == SHUTDOWN_TIMER_IDENT) {
			syslog(LOG_WARNING,
			    "shutdown timed out after 30 seconds; "
			    "forcing serviced exit");
			/*
			 * Do not finish Authority teardown while serviced is alive.
			 * The procdesc is explicit authority through its signal
			 * shield; wait for NOTE_EXIT to call shutdown_finish().
			 */
			bootstrap_signal(SIGKILL);
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
