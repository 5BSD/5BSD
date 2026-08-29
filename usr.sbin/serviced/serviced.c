/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced — service manager and naming registry.
 *
 * Started by authorityd as its single child.  Inherits a mac_capability channel
 * on fd 3 for requesting activation tokens, channels, coalitions, named
 * capability-service descriptors, and kernel-module prerequisites from the
 * authority.  Scans capability bundles, dependency-sorts, pdfork/execs
 * services, and manages their lifecycle (restart, shutdown).
 *
 * Startup sequence:
 *   1. Inherit channel fd from AUTHORITYD_CHANNEL_FD env (fd 3)
 *   2. Create kqueue, register channel + signals
 *   3. Scan bundle directories
 *   4. Dependency sort
 *   5. Run /etc/rc, then fork/exec services (requesting tokens from authorityd)
 *   6. Send AUTHORITY_OP_READY to authorityd to confirm this boot converged
 *   7. Enter event loop
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_capprotect_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcapbundle.h>
#include <capability.h>

#include "serviced.h"
#include "serviced_audit.h"
#include "fd_budget.h"
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
			    (int)kev->ident == sd.authority_channel_fd) {
				if (kev->flags & EV_EOF) {
					syslog(LOG_CRIT,
					    "authority died, stopping all services");
					SERVICED_PROBE_AUTHORITY_DISCONNECTED();
					/* Loss of the capability-minting authority
					 * is a security-relevant integrity event. */
					serviced_audit(AUE_SERVICED_AUTHORITY,
					    getuid(), EIO,
					    "authority channel disconnected; "
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

			/* Path and queue-directory (vnode) activation sources. */
			if (kev->filter == EVFILT_VNODE) {
				activation_path_event(kev, serviced_kq);
				continue;
			}

			/* Mount (EVFILT_FS) activation sources. */
			if (kev->filter == EVFILT_FS) {
				activation_mount_event(kev, serviced_kq);
				continue;
			}

			/*
			 * Socket activation sources — manager-owned listeners.
			 * Checked before the generic EVFILT_READ channel handling
			 * so a listen fd (armed with udata=svc) is routed by fd
			 * ownership and never mistaken for a control/channel fd;
			 * the two fd sets are disjoint.
			 */
			if (kev->filter == EVFILT_READ &&
			    activation_socket_owns((int)kev->ident)) {
				activation_socket_event(kev, serviced_kq);
				continue;
			}

			/*
			 * Restart, stop-kill, on-demand, launch, and periodic
			 * activation timers.
			 */
			if (kev->filter == EVFILT_TIMER) {
				if (on_demand_is_timer(kev->ident))
					on_demand_timeout(kev->ident,
					    serviced_kq);
				else if (svc_launch_timer_owns(kev->ident))
					svc_launch_timer_fire(kev->ident,
					    serviced_kq);
				else if (activation_timer_owns(kev->ident))
					activation_timer_fire(kev->ident,
					    serviced_kq);
				else
					supervisor_handle_timer(kev);
				continue;
			}

			/* Minted user-domain lookup channels (§21/§22). */
			if ((kev->filter == EVFILT_READ ||
			    kev->filter == EVFILT_WRITE) &&
			    domain_channel_owns_event(kev->ident)) {
				domain_channel_event(kev, serviced_kq);
				continue;
			}

			/* Service channel events. */
			if ((kev->filter == EVFILT_READ ||
			    kev->filter == EVFILT_WRITE) &&
			    kev->udata != NULL) {
				struct svc_runtime *svc = kev->udata;

				/* An async launch's in-flight component-session
				 * channel is armed with the svc as udata; route
				 * its readiness to the launch state machine. */
				if (svc_launch_owns_event(svc, kev->ident))
					svc_launch_channel_event(svc,
					    serviced_kq);
				else
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

/*
 * Validate the pkgbase-installed default identity.  serviced deliberately
 * never edits passwd or group databases during startup: installation,
 * upgrade, rollback, and immutable-/etc handling belong to pkgbase.
 */
static int
validate_default_identity(void)
{
	struct group *group;
	struct passwd *user;

	group = getgrnam(SERVICED_DEFAULT_GROUP);
	user = getpwnam(SERVICED_DEFAULT_USER);
	if (group == NULL || user == NULL) {
		errno = ENOENT;
		goto fail;
	}
	if (user->pw_uid == 0 || user->pw_gid != group->gr_gid ||
	    strcmp(user->pw_dir, "/nonexistent") != 0 ||
	    strcmp(user->pw_shell, "/usr/sbin/nologin") != 0) {
		errno = EPERM;
		goto fail;
	}
	syslog(LOG_INFO, "default service identity validated: %s:%s "
	    "uid=%ju gid=%ju",
	    SERVICED_DEFAULT_USER, SERVICED_DEFAULT_GROUP,
	    (uintmax_t)user->pw_uid, (uintmax_t)group->gr_gid);
	SERVICED_PROBE_IDENTITY_VALIDATE(SERVICED_DEFAULT_USER,
	    SERVICED_DEFAULT_GROUP, 0);
	serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), 0,
	    "pkgbase default identity validated user=%s group=%s uid=%ju gid=%ju",
	    SERVICED_DEFAULT_USER, SERVICED_DEFAULT_GROUP,
	    (uintmax_t)user->pw_uid, (uintmax_t)group->gr_gid);
	return (0);

fail:
	SERVICED_PROBE_IDENTITY_VALIDATE(SERVICED_DEFAULT_USER,
	    SERVICED_DEFAULT_GROUP, errno != 0 ? errno : EIO);
	syslog(LOG_CRIT, "invalid pkgbase default service identity %s:%s: %m",
	    SERVICED_DEFAULT_USER, SERVICED_DEFAULT_GROUP);
	serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(),
	    errno != 0 ? errno : EIO,
	    "pkgbase default identity validation failed user=%s group=%s",
	    SERVICED_DEFAULT_USER, SERVICED_DEFAULT_GROUP);
	return (-1);
}

int
main(int argc, char *argv[])
{
	struct kevent kev;
	const char *channel_fd_str, *s;
	int ch;

	/* Present as "Serviced" in ps/top, distinct from lowercase base daemons. */
	setproctitle("-Serviced");

	memset(&sd, 0, sizeof(sd));
	sd.authority_channel_fd = -1;
	sd.channel_svc_fd = -1;
	sd.coalition_svc_fd = -1;
	sd.capprotect_fd = -1;
	sd.identity_fd = -1;
	storage_lifecycle_reset();

	/*
	 * LOG_CONS: during early boot serviced runs before syslogd exists, so
	 * syslog() to /var/run/log is undeliverable; LOG_CONS makes those
	 * messages fall back to /dev/console instead of vanishing.  Essential
	 * for diagnosing a boot that wedges before convergence.
	 */
	openlog("serviced", LOG_PID | LOG_NDELAY | LOG_PERROR | LOG_CONS,
	    LOG_DAEMON);

	/* Parse arguments. */
	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
		}
	}

	/* Inherit channel fd. */
	channel_fd_str = getenv("AUTHORITYD_CHANNEL_FD");
	if (channel_fd_str != NULL) {
		char *endp;
		long val;

		errno = 0;
		val = strtol(channel_fd_str, &endp, 10);
		if (errno != 0 || *endp != '\0' ||
		    val < 0 || val > INT_MAX) {
			syslog(LOG_ERR, "invalid AUTHORITYD_CHANNEL_FD: %s",
			    channel_fd_str);
			return (1);
		}
		sd.authority_channel_fd = (int)val;
	} else {
		syslog(LOG_ERR, "AUTHORITYD_CHANNEL_FD not set");
		return (1);
	}

	/* Non-blocking so authority_rpc can timeout instead of hanging. */
	(void)fcntl(sd.authority_channel_fd, F_SETFL, O_NONBLOCK);

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
	 * Lock down inherited descriptors.  The authority channel and delegate
	 * fds are for serviced only — they must not be inherited by
	 * child services (clofork), leaked via exec (cloexec), or
	 * transferred over a channel (xfer=none).
	 */
	{
		int lockfds[] = {
			sd.authority_channel_fd,
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

	if (validate_default_identity() == -1)
		return (1);
	if (serviced_fd_budget_raise_limit() == -1) {
		syslog(LOG_CRIT,
		    "cannot raise descriptor limit: %m");
		return (1);
	}
	if (serviced_fd_budget_init() == -1) {
		syslog(LOG_CRIT,
		    "cannot establish descriptor emergency reserve: %m");
		return (1);
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

	/* Register authority channel for read (detect EOF = authority died). */
	EV_SET(&kev, sd.authority_channel_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "kevent channel: %m");
		return (1);
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
	 * SIGCONT.  Authorityd retains control through the procdesc returned by
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
		struct cp_request cp_req;
		size_t reply_length, reply_nfds;

		memset(&cp_req, 0, sizeof(cp_req));
		cp_req.op = CP_OP_SHIELD;
		cp_req.flags = CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_WAIT |
		    CP_SF_SIGKILL | CP_SF_SIGCONT | CP_SF_SCHED |
		    CP_SF_CORE | CP_SF_KTRACE;
		/*
		 * Test harnesses need to induce a manager crash to prove
		 * supervisor loss is observable; the shield otherwise denies
		 * ambient SIGKILL by design.  Only authorityd's environment
		 * allowlist can set this.
		 */
		if (getenv("SERVICED_TEST_SHIELD_NO_SIGKILL") != NULL)
			cp_req.flags &= ~CP_SF_SIGKILL;

		reply_length = 0;
		reply_nfds = 0;
		if (capability_kernel_call(sd.capprotect_fd, &cp_req,
		    sizeof(cp_req), NULL, 0, NULL, &reply_length, NULL,
		    &reply_nfds) == -1) {
			syslog(LOG_CRIT, "capprotect shield: %m");
			return (1);
		}
		syslog(LOG_INFO, "capprotect shield active");
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

	/*
	 * Arm timer and path activation sources (Phase 5).  These create demand
	 * for their units; a purely timer/path-activated unit gets its stopped
	 * runtime slot here, since startup only launches boot units.
	 */
	(void)activation_register_all(serviced_kq);

	/*
	 * Set up the control socket only now, after startup_launch_system.
	 * sctl_setup mounts serviced's own tmpfs runtime home and binds the
	 * socket there, so this no longer depends on /etc/rc having remounted /
	 * read-write; it stays here so the rendezvous appears once the plane is
	 * far enough up to serve control clients.
	 */
	if (sctl_setup() == 0) {
		EV_SET(&kev, sctl_fd(), EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(serviced_kq, &kev, 1, NULL, 0, NULL) == -1)
			syslog(LOG_WARNING, "kevent sctl: %m");
	}

	/*
	 * Boot has converged: /etc/rc ran and native services were launched.
	 * Tell PID 1 through the per-instance authenticated channel, rather
	 * than a pathname which a persistent root can carry across reboots.
	 * Individual service failures do not block convergence; only serviced
	 * never reaching this point (crash or wedge) triggers PID 1 recovery.
	 */
	if (authority_send_ready(sd.authority_channel_fd) != 0) {
		syslog(LOG_ERR, "failed to send convergence READY to authorityd");
		return (1);
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
	domain_channel_teardown();
	supervisor_teardown_state();
	bundle_registry_teardown();
	sctl_teardown();
	serviced_fd_budget_fini();

	syslog(LOG_INFO, "serviced exiting");
	close(serviced_kq);
	return (0);
}
