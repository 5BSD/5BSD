/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced — service manager and naming registry.
 *
 * Started by oracled as its single child.  Inherits a mac_capability channel
 * on fd 3 for requesting activation tokens, channels, coalitions, named
 * capability-service descriptors, and kernel-module prerequisites from the
 * oracle.  Scans capability bundles, dependency-sorts, pdfork/execs
 * services, and manages their lifecycle (restart, shutdown).
 *
 * Startup sequence:
 *   1. Inherit channel fd from ORACLED_CHANNEL_FD env (fd 3)
 *   2. Create kqueue, register channel + signals
 *   3. Send ORACLE_OP_READY to oracled
 *   4. Scan bundle directories
 *   5. Dependency sort
 *   6. Fork/exec services (requesting tokens from oracled)
 *   7. Enter event loop
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "serviced.h"
#include "serviced_audit.h"
#include "serviced_probes.h"

struct serviced_state sd;
int serviced_kq;

const char *serviced_bundle_dir_system = SERVICED_BUNDLE_DIR_SYSTEM_DEFAULT;
const char *serviced_bundle_dir_user = SERVICED_BUNDLE_DIR_USER_DEFAULT;

static void
add_signal_event(int kq, int sig)
{
	struct kevent kev;

	(void)signal(sig, SIG_IGN);
	EV_SET(&kev, sig, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_CRIT, "kevent signal %d: %m", sig);
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
			    (int)kev->ident == sd.oracle_channel_fd) {
				if (kev->flags & EV_EOF) {
					syslog(LOG_CRIT,
					    "oracle died, stopping all services");
					SERVICED_PROBE_ORACLE_DISCONNECTED();
					/* Loss of the capability-minting authority
					 * is a security-relevant integrity event. */
					serviced_audit(AUE_SERVICED_ORACLE,
					    getuid(), EIO,
					    "oracle channel disconnected; "
					    "stopping all services");
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

			/* Restart, stop-kill, and on-demand timers. */
			if (kev->filter == EVFILT_TIMER) {
				if (on_demand_is_timer(kev->ident))
					on_demand_timeout(kev->ident,
					    serviced_kq);
				else
					supervisor_handle_timer(kev);
				continue;
			}

			/* Service channel events. */
			if (kev->filter == EVFILT_READ &&
			    kev->udata != NULL) {
				supervisor_handle_channel(kev);
				continue;
			}
		}
	}
}

static void
usage(void)
{

	fprintf(stderr, "usage: serviced\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct kevent kev;
	const char *channel_fd_str, *s;
	int ch;

	memset(&sd, 0, sizeof(sd));
	sd.oracle_channel_fd = -1;
	sd.channel_svc_fd = -1;
	sd.coalition_svc_fd = -1;
	sd.capprotect_fd = -1;
	sd.identity_fd = -1;

	openlog("serviced", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

	/* Parse arguments. */
	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
		}
	}

	/* Inherit channel fd. */
	channel_fd_str = getenv("ORACLED_CHANNEL_FD");
	if (channel_fd_str != NULL) {
		char *endp;
		long val;

		errno = 0;
		val = strtol(channel_fd_str, &endp, 10);
		if (errno != 0 || *endp != '\0' ||
		    val < 0 || val > INT_MAX) {
			syslog(LOG_ERR, "invalid ORACLED_CHANNEL_FD: %s",
			    channel_fd_str);
			return (1);
		}
		sd.oracle_channel_fd = (int)val;
	} else {
		syslog(LOG_ERR, "ORACLED_CHANNEL_FD not set");
		return (1);
	}

	/* Non-blocking so oracle_rpc can timeout instead of hanging. */
	(void)fcntl(sd.oracle_channel_fd, F_SETFL, O_NONBLOCK);

	/* Inherit delegated service instance fds (optional). */
	{
		char *endp;
		long val;

		s = getenv("SERVICED_CHANNEL_SVC_FD");
		if (s != NULL) {
			errno = 0;
			val = strtol(s, &endp, 10);
			if (errno != 0 || *endp != '\0' ||
			    val < 0 || val > INT_MAX)
				sd.channel_svc_fd = -1;
			else
				sd.channel_svc_fd = (int)val;
		}
		s = getenv("SERVICED_COALITION_SVC_FD");
		if (s != NULL) {
			errno = 0;
			val = strtol(s, &endp, 10);
			if (errno != 0 || *endp != '\0' ||
			    val < 0 || val > INT_MAX)
				sd.coalition_svc_fd = -1;
			else
				sd.coalition_svc_fd = (int)val;
		}
		s = getenv("SERVICED_CAPPROTECT_FD");
		if (s != NULL) {
			errno = 0;
			val = strtol(s, &endp, 10);
			if (errno != 0 || *endp != '\0' ||
			    val < 0 || val > INT_MAX)
				sd.capprotect_fd = -1;
			else
				sd.capprotect_fd = (int)val;
		}
		s = getenv("SERVICED_IDENTITY_FD");
		if (s != NULL) {
			errno = 0;
			val = strtol(s, &endp, 10);
			if (errno != 0 || *endp != '\0' ||
			    val < 0 || val > INT_MAX)
				sd.identity_fd = -1;
			else
				sd.identity_fd = (int)val;
		}
	}
	if (sd.channel_svc_fd >= 0) {
		(void)fcntl(sd.channel_svc_fd, F_SETFL, O_NONBLOCK);
		syslog(LOG_INFO, "inherited service fds: channel=%d "
		    "coalition=%d capprotect=%d identity=%d",
		    sd.channel_svc_fd, sd.coalition_svc_fd,
		    sd.capprotect_fd, sd.identity_fd);
	}
	if (sd.coalition_svc_fd >= 0)
		(void)fcntl(sd.coalition_svc_fd, F_SETFL, O_NONBLOCK);

	/* Override bundle directories from environment (for testing). */
	s = getenv("SERVICED_BUNDLE_DIR_SYSTEM");
	if (s != NULL && s[0] != '\0')
		serviced_bundle_dir_system = s;
	s = getenv("SERVICED_BUNDLE_DIR_USER");
	if (s != NULL && s[0] != '\0')
		serviced_bundle_dir_user = s;

	/*
	 * Lock down inherited descriptors.  The oracle channel and delegate
	 * fds are for serviced only — they must not be inherited by
	 * child services (clofork), leaked via exec (cloexec), or
	 * transferred over a channel (xfer=none).
	 */
	{
		int lockfds[] = {
			sd.oracle_channel_fd,
			sd.channel_svc_fd,
			sd.coalition_svc_fd,
			sd.capprotect_fd,
			sd.identity_fd,
		};
		for (int i = 0; i < (int)(sizeof(lockfds)/sizeof(lockfds[0])); i++) {
			if (lockfds[i] < 0)
				continue;
			if (cap_xfer_limit(lockfds[i], CAP_XFER_NONE) == -1 ||
			    cap_clofork_limit(lockfds[i],
			    CAP_CLOFORK_LOCKED) == -1 ||
			    cap_cloexec_limit(lockfds[i],
			    CAP_CLOEXEC_LOCKED) == -1) {
				syslog(LOG_ERR,
				    "failed to confine inherited fd %d: %m",
				    lockfds[i]);
				return (1);
			}
		}
	}

	/* Create kqueue early — needed for signal handling during setup. */
	serviced_kq = kqueue();
	if (serviced_kq == -1) {
		syslog(LOG_ERR, "kqueue: %m");
		return (1);
	}
	if (cap_xfer_limit(serviced_kq, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(serviced_kq, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(serviced_kq, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_ERR, "kqueue confinement: %m");
		return (1);
	}

	/* Register oracle channel for read (detect EOF = oracle died). */
	EV_SET(&kev, sd.oracle_channel_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "kevent channel: %m");
		return (1);
	}

	/* Set up control socket. */
	if (sctl_setup() == 0) {
		EV_SET(&kev, sctl_fd(), EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1)
			syslog(LOG_WARNING, "kevent sctl: %m");
	}

	/* Register signals. */
	/* A client that closes early must produce EPIPE, not kill the manager. */
	(void)signal(SIGPIPE, SIG_IGN);
	add_signal_event(serviced_kq, SIGTERM);
	add_signal_event(serviced_kq, SIGINT);
	add_signal_event(serviced_kq, SIGHUP);
	add_signal_event(serviced_kq, SIGCHLD);

	/* Initialize bundle registry (scan /Capabilities/System + /Capabilities). */
	if (bundle_registry_init() == -1) {
		syslog(LOG_CRIT, "bundle registry init failed — aborting");
		return (1);
	}

	/*
	 * Apply the shield only after setup, but before READY or launching any
	 * service.  Ambient signal paths are blocked, including SIGKILL and
	 * SIGCONT.  Oracled retains control through the procdesc returned by
	 * pdfork(2); pdkill(2) is explicit capability authority and deliberately
	 * bypasses the ambient credential/MAC signal path.
	 *
	 * CP_SF_VISIBLE remains omitted because syslog delivery may require
	 * process visibility.  Visibility is not authority to modify serviced.
	 */
	if (sd.capprotect_fd < 0) {
		syslog(LOG_CRIT, "capprotect descriptor not delegated");
		return (1);
	} else {
		struct mac_capability_call_args call;
		struct cp_request cp_req;

		memset(&cp_req, 0, sizeof(cp_req));
		cp_req.op = CP_OP_SHIELD;
		cp_req.flags = CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_WAIT |
		    CP_SF_SIGKILL | CP_SF_SIGCONT | CP_SF_SCHED |
		    CP_SF_CORE | CP_SF_KTRACE;

		memset(&call, 0, sizeof(call));
		call.req = &cp_req;
		call.req_len = sizeof(cp_req);

		if (ioctl(sd.capprotect_fd, MAC_CAPABILITY_CALL, &call) == -1) {
			syslog(LOG_CRIT, "capprotect shield: %m");
			return (1);
		}
		syslog(LOG_INFO, "capprotect shield active");
	}

	/* READY means protected and operational, not merely post-exec alive. */
	if (oracle_send_ready(sd.oracle_channel_fd) != 0) {
		syslog(LOG_ERR, "failed to send protected READY to oracled");
		return (1);
	}

	sd.running = true;
	syslog(LOG_INFO, "serviced started, %u bundles registered",
	    bundle_registry_count());
	serviced_audit(AUE_SERVICED_START, getuid(), 0,
	    "serviced started, %u bundles registered",
	    bundle_registry_count());

	/* Launch system services (tier-based parallel). */
	if (startup_launch_system(serviced_kq) != 0) {
		syslog(LOG_ERR, "startup: system service launch failed");
		/* Continue running — on-demand and reload can still work. */
	}

	event_loop();

	/* Graceful shutdown: ensure services are stopping.
	 * supervisor_stop() may have already been called from the
	 * signal handler — it's idempotent (checks sd.nservices). */
	if (!sd.shutting_down)
		supervisor_stop(serviced_kq);
	SERVICED_PROBE_SHUTDOWN_START(sd.nservices);
	{
		struct kevent sevents[8];
		struct timespec drain_start;
		int w, si, sn;

		clock_gettime(CLOCK_MONOTONIC, &drain_start);

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
		{
			struct timespec now;
			uint64_t dur __unused;

			clock_gettime(CLOCK_MONOTONIC, &now);
			dur = (uint64_t)(now.tv_sec - drain_start.tv_sec) *
			    1000000000ULL +
			    (uint64_t)(now.tv_nsec - drain_start.tv_nsec);
			SERVICED_PROBE_SHUTDOWN_DONE(dur);
		}
	}
	on_demand_teardown(serviced_kq);
	supervisor_teardown_state();
	bundle_registry_teardown();
	sctl_teardown();

	syslog(LOG_INFO, "serviced exiting");
	close(serviced_kq);
	return (0);
}
