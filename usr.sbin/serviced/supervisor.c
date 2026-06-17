/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service lifecycle supervisor for serviced.
 *
 * Core lifecycle: startup, process-descriptor events, restart
 * backoff, graceful stop, and orderly shutdown.  All operations
 * integrate with the main kqueue loop.
 *
 * Hot-reload logic lives in reload.c; service channel protocol
 * dispatch lives in svc_proto.c.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <dev/cap_rt/cap_rt_ioctl.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "serviced.h"
#include "serviced_probes.h"

/* Restart backoff parameters. */
#define	RESTART_MIN_UPTIME_SEC	5	/* rapid restart threshold */
#define	RESTART_MAX_DELAY_SEC	30
#define	RESTART_RESET_SEC	60	/* reset counter after stability */

/* Monotonic counters for unique timer idents.  High bit
 * distinguishes stop timers from restart timers. */
static uintptr_t timer_next_ident = 10000;
#define	STOP_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 1))
static uintptr_t stop_timer_next_ident = STOP_TIMER_BIT;

/*
 * Close all service fds and reset runtime state.
 */
static void
svc_close_fds(struct svc_runtime *svc)
{

	if (svc->pd_fd >= 0) {
		close(svc->pd_fd);
		svc->pd_fd = -1;
	}
	if (svc->channel_fd >= 0) {
		close(svc->channel_fd);
		svc->channel_fd = -1;
	}
	if (svc->coalition_fd >= 0) {
		close(svc->coalition_fd);
		svc->coalition_fd = -1;
	}
	if (svc->jail_fd >= 0) {
		jail_remove_jd(svc->jail_fd);
		close(svc->jail_fd);
		svc->jail_fd = -1;
	}
}

/*
 * Release claims for this service's capabilities.  Sends all
 * release messages in a burst, then drains replies in a single
 * blocking window (~100ms worst case regardless of count).
 * The oracle returns EPERM for manifest claims (harmless) and
 * decrements the refcount for dynamic ones.
 */
static void
svc_release_dynamic_claims(struct svc_runtime *svc)
{

	oracle_release_manifest(sd.oracle_channel_fd, &svc->manifest);
}

/*
 * Schedule a delayed restart via EVFILT_TIMER on the kqueue.
 */
void
schedule_restart(struct svc_runtime *svc, int kq)
{
	struct kevent kev;
	unsigned delay;

	delay = svc->restart_count * 2;
	if (delay < 1)
		delay = 1;
	if (delay > RESTART_MAX_DELAY_SEC)
		delay = RESTART_MAX_DELAY_SEC;

	syslog(LOG_INFO, "service %s: scheduling restart in %us",
	    svc->manifest.label, delay);
	SERVICED_PROBE_SVC_RESTART(svc->manifest.label, svc->restart_count);

	svc->timer_ident = timer_next_ident++;
	EV_SET(&kev, svc->timer_ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, delay, svc);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_ERR, "service %s: kevent timer: %m",
		    svc->manifest.label);
	else {
		svc->restart_pending = true;
		SERVICED_PROBE_TIMEOUT_ARM(svc->manifest.label,
		    "restart", delay);
	}
}

static void
schedule_stop_kill(struct svc_runtime *svc, int kq)
{
	struct kevent kev;

	svc->stop_timer_ident = stop_timer_next_ident++;
	EV_SET(&kev, svc->stop_timer_ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS,
	    svc->manifest.stop_timeout, svc);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_ERR, "service %s: stop timer: %m",
		    svc->manifest.label);
	else {
		svc->stop_kill_pending = true;
		SERVICED_PROBE_TIMEOUT_ARM(svc->manifest.label,
		    "stop-kill", (unsigned)svc->manifest.stop_timeout);
	}
}

static void
cancel_stop_timer(struct svc_runtime *svc)
{
	struct kevent kev;

	if (!svc->stop_kill_pending || svc->stop_timer_ident == 0)
		return;

	EV_SET(&kev, svc->stop_timer_ident, EVFILT_TIMER, EV_DELETE,
	    0, 0, NULL);
	(void)kevent(serviced_kq, &kev, 1, NULL, 0, NULL);
	svc->stop_kill_pending = false;
	svc->stop_timer_ident = 0;
}

void
supervisor_handle_procdesc(struct kevent *kev)
{
	struct svc_runtime *svc;
	struct timespec now;
	long uptime_sec;

	svc = kev->udata;

	if ((kev->fflags & NOTE_EXEC) &&
	    svc->state == SVC_STATE_STARTING) {
		/*
		 * NOTE_EXEC confirms the child has exec'd, but don't
		 * promote to RUNNING yet — wait for the SVC_OP_READY
		 * protocol message.  This ensures on-demand waiters
		 * are only drained after the service has registered
		 * its name and is ready to accept connections.
		 */
		syslog(LOG_INFO, "service %s: exec confirmed (pid %jd)",
		    svc->manifest.label, (intmax_t)svc->pid);
		SERVICED_PROBE_SVC_EXEC(svc->manifest.label, svc->pid);
	}

	if (kev->fflags & NOTE_EXIT) {
		int was_stopping;
		int exit_status;
		bool reload_pending, remove_pending;

		exit_status = (int)kev->data;

		if (WIFEXITED(exit_status))
			syslog(LOG_INFO, "service %s: exited status %d "
			    "(pid %jd)", svc->manifest.label,
			    WEXITSTATUS(exit_status),
			    (intmax_t)svc->pid);
		else if (WIFSIGNALED(exit_status))
			syslog(LOG_WARNING, "service %s: killed by signal %d "
			    "(pid %jd)", svc->manifest.label,
			    WTERMSIG(exit_status),
			    (intmax_t)svc->pid);

		SERVICED_PROBE_SVC_EXIT(svc->manifest.label,
		    svc->pid, exit_status);

		was_stopping = (svc->state == SVC_STATE_STOPPING);
		reload_pending = svc->reload_pending;
		remove_pending = svc->remove_pending;

		waitpid(svc->pid, NULL, WNOHANG);
		cancel_stop_timer(svc);
		naming_remove_owner(svc);

		/* Release dynamic claims for this service. */
		svc_release_dynamic_claims(svc);

		svc_close_fds(svc);
		svc->state = SVC_STATE_STOPPED;

		if (was_stopping && remove_pending) {
			unsigned idx;

			idx = (unsigned)(svc - sd.services);
			svc_remove(idx);
			svc_reregister_kevents(serviced_kq);
			return;
		}

		if (was_stopping && reload_pending) {
			svc->manifest = svc->pending_manifest;
			memset(&svc->pending_manifest, 0,
			    sizeof(svc->pending_manifest));
			svc->reload_pending = false;
			svc->restart_count = 0;
			svc_exec(svc, serviced_kq);
			return;
		}

		/* No restart if we asked it to stop. */
		if (was_stopping)
			return;

		switch (svc->manifest.restart) {
		case SVC_RESTART_NEVER:
			return;
		case SVC_RESTART_ON_FAILURE:
			if (WIFEXITED(exit_status) &&
			    WEXITSTATUS(exit_status) == 0)
				return;
			break;
		case SVC_RESTART_ALWAYS:
			break;
		}

		svc->restart_count++;

		/* Reset counter if the service ran for a while. */
		clock_gettime(CLOCK_MONOTONIC, &now);
		uptime_sec = now.tv_sec - svc->last_start.tv_sec;
		if (uptime_sec >= RESTART_RESET_SEC)
			svc->restart_count = 1;

		/* Circuit breaker: disable service after too many failures. */
		if (svc->restart_count >= svc->manifest.max_failures) {
			syslog(LOG_CRIT, "service %s: failed %u times, "
			    "disabling", svc->manifest.label,
			    svc->restart_count);
			SERVICED_PROBE_SVC_DISABLED(svc->manifest.label,
			    svc->restart_count);
			svc->state = SVC_STATE_STOPPED;
			return;
		}

		/* Backoff if it died too fast. */
		if (uptime_sec < RESTART_MIN_UPTIME_SEC) {
			schedule_restart(svc, serviced_kq);
		} else {
			syslog(LOG_INFO, "service %s: restarting "
			    "(count %u)", svc->manifest.label,
			    svc->restart_count);
			svc_exec(svc, serviced_kq);
		}
	}
}

void
supervisor_handle_timer(struct kevent *kev)
{
	struct svc_runtime *svc;

	svc = kev->udata;

	if (svc->stop_kill_pending && kev->ident == svc->stop_timer_ident) {
		svc->stop_kill_pending = false;
		svc->stop_timer_ident = 0;
		SERVICED_PROBE_TIMEOUT_FIRE(svc->manifest.label, "stop-kill");
		syslog(LOG_WARNING, "service %s: stop timeout, "
		    "sending SIGKILL", svc->manifest.label);
		if (svc->coalition_fd >= 0) {
			if (caprt_coalition_terminate(svc->coalition_fd) == -1)
				syslog(LOG_WARNING,
				    "service %s: coalition terminate: %m",
				    svc->manifest.label);
		} else if (svc->pd_fd >= 0) {
			pdkill(svc->pd_fd, SIGKILL);
		}
		return;
	}

	if (svc->restart_pending && kev->ident == svc->timer_ident) {
		svc->restart_pending = false;
		svc->timer_ident = 0;
		SERVICED_PROBE_TIMEOUT_FIRE(svc->manifest.label, "restart");
		if (sd.shutting_down) {
			syslog(LOG_INFO, "service %s: restart cancelled "
			    "(shutting down)", svc->manifest.label);
			return;
		}
		syslog(LOG_INFO, "service %s: restart timer fired",
		    svc->manifest.label);
		svc_exec(svc, serviced_kq);
	}
}

/*
 * Gracefully stop a single service: SIGTERM via pdkill,
 * then kqueue timer-driven SIGKILL if still alive.
 */
void
svc_graceful_stop(struct svc_runtime *svc, int kq)
{

	if (svc->state != SVC_STATE_RUNNING &&
	    svc->state != SVC_STATE_STARTING)
		return;

	svc->state = SVC_STATE_STOPPING;
	syslog(LOG_INFO, "service %s: stopping (pid %jd)",
	    svc->manifest.label, (intmax_t)svc->pid);
	SERVICED_PROBE_SVC_STOP(svc->manifest.label, svc->pid);

	if (svc->coalition_fd >= 0) {
		if (caprt_coalition_graceful(svc->coalition_fd, SIGTERM,
		    (unsigned)svc->manifest.stop_timeout * 1000) == -1) {
			syslog(LOG_WARNING,
			    "service %s: coalition graceful: %m",
			    svc->manifest.label);
			if (svc->pd_fd >= 0)
				pdkill(svc->pd_fd, SIGTERM);
			schedule_stop_kill(svc, kq);
		}
	} else {
		if (svc->pd_fd >= 0)
			pdkill(svc->pd_fd, SIGTERM);
		schedule_stop_kill(svc, kq);
	}
}

void
supervisor_stop(int kq)
{
	unsigned i;

	if (sd.services == NULL || sd.nservices == 0)
		return;

	syslog(LOG_INFO, "supervisor: stopping %u services", sd.nservices);

	/* Stop in reverse dependency order.  Services that are already
	 * stopped or waiting for a restart timer are removed immediately.
	 * Running services get graceful stop + remove on NOTE_EXIT. */
	for (i = sd.nservices; i > 0; i--) {
		struct svc_runtime *svc = &sd.services[i - 1];

		/* Cancel any pending restart timer. */
		if (svc->restart_pending && svc->timer_ident != 0) {
			struct kevent kev;
			EV_SET(&kev, svc->timer_ident, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			(void)kevent(kq, &kev, 1, NULL, 0, NULL);
			svc->restart_pending = false;
		}

		if (svc->state == SVC_STATE_STOPPED) {
			svc_remove(i - 1);
			continue;
		}

		svc->remove_pending = true;
		svc_graceful_stop(svc, kq);
	}
	svc_reregister_kevents(kq);
}

bool
supervisor_is_stopped(void)
{

	return (sd.services == NULL || sd.nservices == 0);
}

void
supervisor_teardown_state(void)
{

	free(sd.services);
	sd.services = NULL;
	sd.nservices = 0;
	syslog(LOG_INFO, "supervisor: all services stopped");
}
