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
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "serviced.h"
#include "serviced_audit.h"
#include "serviced_probes.h"
#include "serviced_svc_proto.h"

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
 * Idle-shutdown timers carry a distinct high bit so their idents never
 * collide with restart, stop-kill, on-demand, or async-launch timers.  Bit
 * (width-3) is unused by those ranges, so the event loop routes these to
 * supervisor_handle_timer(), which matches them per-service.
 */
#define	IDLE_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 3))
static uintptr_t idle_timer_next_ident = IDLE_TIMER_BIT;

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
	svc_channel_close(svc);
	if (svc->coalition_fd >= 0) {
		close(svc->coalition_fd);
		svc->coalition_fd = -1;
	}

	/* Remove the per-instance runtime container (recreated on next launch). */
	svc_run_container_remove(svc->manifest.label);
}

/*
 * Release claims for this service's capabilities.  Sends all
 * release messages in a burst, then drains replies in a single
 * blocking window (~100ms worst case regardless of count).
 * The authority returns EPERM for manifest claims (harmless) and
 * decrements the refcount for dynamic ones.
 */
static void
svc_release_dynamic_claims(struct svc_runtime *svc)
{

	authority_release_manifest(sd.authority_channel_fd, &svc->manifest);
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

/*
 * Restart a service now, but tolerate an exec-time failure.  A plain svc_exec()
 * that fails (fd-budget denial, calloc ENOMEM, a transient mint failure) leaves
 * the unit STOPPED with no timer armed, and since the process never started
 * there is no NOTE_EXIT to retrigger recovery — the daemon wedges silently until
 * some unrelated lookup or reload happens to relaunch it.  Count the failure
 * against the circuit breaker (so a permanently-broken exec is eventually
 * disabled instead of spinning) and otherwise arm a backoff retry, matching the
 * fail-soft/retry behaviour of the death path.
 */
static void
svc_restart_now(struct svc_runtime *svc, int kq)
{

	if (svc_exec(svc, kq) != -1)
		return;
	if (++svc->restart_count >= svc->manifest.max_failures) {
		syslog(LOG_CRIT, "service %s: exec failed %u times, disabling",
		    svc->manifest.label, svc->restart_count);
		SERVICED_PROBE_SVC_DISABLED(svc->manifest.label,
		    svc->restart_count);
		svc->state = SVC_STATE_STOPPED;
		return;
	}
	syslog(LOG_WARNING, "service %s: exec failed (%u), scheduling retry",
	    svc->manifest.label, svc->restart_count);
	schedule_restart(svc, kq);
}

void
svc_cancel_restart(struct svc_runtime *svc, int kq)
{
	struct kevent kev;

	if (!svc->restart_pending || svc->timer_ident == 0)
		return;
	EV_SET(&kev, svc->timer_ident, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	(void)kevent(kq, &kev, 1, NULL, 0, NULL);
	svc->restart_pending = false;
	svc->timer_ident = 0;
}

/*
 * Cancel a pending provider idle-shutdown timer.  No-op if none is armed.
 */
void
cancel_idle_timer(struct svc_runtime *svc, int kq)
{
	struct kevent kev;

	if (svc->idle_timer_ident == 0)
		return;
	EV_SET(&kev, svc->idle_timer_ident, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	(void)kevent(kq, &kev, 1, NULL, 0, NULL);
	svc->idle_timer_ident = 0;
}

/*
 * Arm (or re-arm) the provider idle-shutdown timer for svc->idle_timeout_sec.
 * Re-arming resets the countdown.  No-op when no idle timeout is requested.
 */
void
arm_idle_timer(struct svc_runtime *svc, int kq)
{
	struct kevent kev;

	if (svc->idle_timeout_sec == 0)
		return;
	cancel_idle_timer(svc, kq);
	svc->idle_timer_ident = idle_timer_next_ident++;
	EV_SET(&kev, svc->idle_timer_ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, 0, svc->idle_timeout_sec * 1000, svc);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "service %s: idle timer: %m",
		    svc->manifest.label);
		svc->idle_timer_ident = 0;
	} else
		SERVICED_PROBE_TIMEOUT_ARM(svc->manifest.label, "idle",
		    svc->idle_timeout_sec);
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

/*
 * Post-STOPPED handling shared by every way an RC unit reaches STOPPED (a
 * clean onestop exit, an onestop launch failure, or the onestop backstop
 * timer): honour a pending remove (shutdown / servicectl remove) and a pending
 * reload (swap the manifest and re-exec).  A servicectl restart is driven
 * client-side — it stops, then retries start once the unit is STOPPED — so no
 * server-side restart_pending handling is needed here.  svc is left STOPPED on
 * entry; callers must have cleared rc_stopping and released the descriptor.
 */
static void
supervisor_rc_post_stop(struct svc_runtime *svc)
{

	if (svc->remove_pending) {
		unsigned idx;

		idx = (unsigned)(svc - sd.services);
		svc_remove(idx);
		svc_reregister_kevents(serviced_kq);
		return;
	}
	if (svc->reload_pending) {
		svc->manifest = svc->pending_manifest;
		memset(&svc->pending_manifest, 0, sizeof(svc->pending_manifest));
		svc->reload_pending = false;
		svc->restart_count = 0;
		if (svc_exec(svc, serviced_kq) == -1)
			syslog(LOG_ERR, "service %s: reload re-exec failed; "
			    "left stopped", svc->manifest.label);
	}
}

/*
 * NOTE_EXIT handling for RC and ONESHOT units.  The process that exited is
 * the start (or stop) command, not a supervised daemon: an rc daemon
 * daemonizes and reparents to init, so serviced tracks only the command's
 * result.  exit 0 => the unit started (RC -> RUNNING) or the task
 * completed (ONESHOT -> DONE); a stop command completing => STOPPED.  None
 * of the native teardown (naming, dynamic claims, on-demand, channel and
 * coalition fds) applies — these units have none of that.
 *
 * An RC unit running its "onestop" command is flagged by svc->rc_stopping;
 * that flag, not the unit state, is what tells this exit apart from an
 * onestart exit, and it drives the transition to STOPPED plus the shared
 * post-stop handling.
 */
static void
supervisor_command_exited(struct svc_runtime *svc, int exit_status)
{
	bool ok, was_stopping, rc_stopping;

	ok = WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 0;
	rc_stopping = svc->rc_stopping;
	was_stopping = (svc->state == SVC_STATE_STOPPING);

	waitpid(svc->pid, NULL, WNOHANG);
	cancel_stop_timer(svc);
	if (svc->pd_fd >= 0) {
		(void)close(svc->pd_fd);	/* EVFILT_PROCDESC auto-removed */
		svc->pd_fd = -1;
	}
	svc->pid = 0;

	if (rc_stopping) {
		/* The "service <label> onestop" command completed. */
		svc->rc_stopping = false;
		svc->state = SVC_STATE_STOPPED;
		if (ok)
			syslog(LOG_INFO, "rc unit %s: stopped",
			    svc->manifest.label);
		else
			syslog(LOG_WARNING, "rc unit %s: onestop failed "
			    "(status %#x); forcing stopped",
			    svc->manifest.label, exit_status);
		supervisor_rc_post_stop(svc);
		return;
	}

	if (was_stopping) {
		svc->state = SVC_STATE_STOPPED;
		syslog(LOG_INFO, "unit %s: stopped", svc->manifest.label);
		return;
	}
	if (svc->kind == SVC_KIND_ONESHOT) {
		svc->state = ok ? SVC_STATE_DONE : SVC_STATE_STOPPED;
		if (ok)
			syslog(LOG_INFO, "oneshot %s: complete",
			    svc->manifest.label);
		else
			syslog(LOG_ERR, "oneshot %s: failed (status %#x)",
			    svc->manifest.label, exit_status);
		return;
	}
	/* RC */
	svc->state = ok ? SVC_STATE_RUNNING : SVC_STATE_STOPPED;
	if (ok)
		syslog(LOG_INFO, "rc unit %s: started", svc->manifest.label);
	else
		syslog(LOG_ERR, "rc unit %s: onestart failed (status %#x)",
		    svc->manifest.label, exit_status);
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
		 * NOTE_EXEC confirms the child has exec'd.  Capability-mode
		 * entry, observed independently through the process
		 * descriptor, is the authoritative readiness boundary.
		 */
		syslog(LOG_INFO, "service %s: exec confirmed (pid %jd)",
		    svc->manifest.label, (intmax_t)svc->pid);
		SERVICED_PROBE_SVC_EXEC(svc->manifest.label, svc->pid);
	}

	if ((kev->fflags & NOTE_CAPMODE) != 0 &&
	    (kev->fflags & NOTE_EXIT) == 0 &&
	    svc->state == SVC_STATE_STARTING) {
		int in_capmode;

		in_capmode = pdincapmode(svc->pd_fd);
		if (in_capmode == 1) {
			svc->state = SVC_STATE_RUNNING;
			syslog(LOG_INFO,
			    "service %s: capability sandbox entered%s",
			    svc->manifest.label,
			    svc->protocol_ready ? ", application ready" :
			    ", application readiness pending");
			SERVICED_PROBE_SVC_CAPMODE(svc->manifest.label,
			    svc->pid, svc->protocol_ready);
			serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), 0,
			    "svc=%s pid=%jd phase=capmode-ready "
			    "protocol_ready=%d", svc->manifest.label,
			    (intmax_t)svc->pid, svc->protocol_ready);
			if (svc->protocol_ready)
				on_demand_check_ready(svc, serviced_kq);
		} else {
			int error;

			error = in_capmode == -1 ? errno : EPROTO;
			syslog(LOG_ERR,
			    "service %s: unverified NOTE_CAPMODE: %s",
			    svc->manifest.label, strerror(error));
			SERVICED_PROBE_SVC_CAPMODE(svc->manifest.label,
			    svc->pid, -error);
			serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), error,
			    "svc=%s pid=%jd phase=capmode-ready",
			    svc->manifest.label, (intmax_t)svc->pid);
		}
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

		/*
		 * RC/ONESHOT units are judged by their command's exit; they
		 * have no capability-mode daemon to supervise or tear down.
		 */
		if (svc->kind == SVC_KIND_RC ||
		    svc->kind == SVC_KIND_ONESHOT) {
			supervisor_command_exited(svc, exit_status);
			return;
		}

		was_stopping = (svc->state == SVC_STATE_STOPPING);
		reload_pending = svc->reload_pending;
		remove_pending = svc->remove_pending;

		waitpid(svc->pid, NULL, WNOHANG);
		cancel_stop_timer(svc);
		/*
		 * The process is gone, so any idle timer armed for it (e.g. a
		 * crash while an idle countdown was pending) is stale and must
		 * be dropped before a restart reuses this slot.
		 */
		cancel_idle_timer(svc, serviced_kq);
		on_demand_provider_failed(svc,
		    was_stopping ? ESHUTDOWN : ECONNRESET, serviced_kq);
		on_demand_requester_gone(svc, serviced_kq);
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
			if (svc_exec(svc, serviced_kq) == -1)
				syslog(LOG_ERR,
				    "service %s: reload re-exec failed; "
				    "left stopped", svc->manifest.label);
			return;
		}

		/*
		 * Idle stop: the provider was gracefully stopped because it went
		 * idle.  Keep the runtime slot, its manifest, and its bundle
		 * origin so the next lookup relaunches it on demand.  Reset the
		 * slot to the same fresh, relaunchable state an on-demand launch
		 * starts from: every name_state[] entry returns to
		 * SVC_NAME_UNCLAIMED (via svc_runtime_init_fds) so the relaunched
		 * process re-claims each provides[] name from scratch.  The
		 * published names were already dropped by naming_remove_owner()
		 * above, so a lookup now misses and triggers on_demand relaunch.
		 */
		if (svc->idle_stop_pending) {
			int saved_listen[SERVICED_MAX_ACTIVATION_SOCKETS];
			unsigned saved_nlisten;
			int saved_path_fd, saved_queue_fd;
			uintptr_t saved_mount_ident;

			/*
			 * Activation sources (socket listeners, path watch, queue
			 * directory, mount watch) OUTLIVE the unit's stop cycles —
			 * they must keep firing to re-activate it on demand.
			 * svc_runtime_init_fds() would reset them all to -1/0
			 * WITHOUT closing the fds or removing their kevents (leaking
			 * the listener/queue fd and orphaning a level-triggered
			 * registration).  Snapshot and restore ALL of them across the
			 * fresh-slot reset — the queue fd and mount ident were
			 * previously dropped here, so after the first idle stop a
			 * queue_directory/on_mount unit leaked its fd and its
			 * activation went permanently dead.
			 */
			memcpy(saved_listen, svc->activation_listen_fds,
			    sizeof(saved_listen));
			saved_nlisten = svc->nactivation_listen;
			saved_path_fd = svc->activation_path_fd;
			saved_queue_fd = svc->activation_queue_fd;
			saved_mount_ident = svc->activation_mount_ident;

			svc->pid = 0;
			svc->launch_id = 0;
			svc->quiesce_pending = false;
			svc->restart_count = 0;
			svc->idle_stop_pending = false;
			svc->idle_timeout_sec = 0;
			svc_runtime_init_fds(svc);
			memcpy(svc->activation_listen_fds, saved_listen,
			    sizeof(saved_listen));
			svc->nactivation_listen = saved_nlisten;
			svc->activation_path_fd = saved_path_fd;
			svc->activation_queue_fd = saved_queue_fd;
			svc->activation_mount_ident = saved_mount_ident;
			svc->state = SVC_STATE_STOPPED;
			syslog(LOG_INFO, "service %s: stopped for idle; "
			    "reservations kept for on-demand relaunch",
			    svc->manifest.label);
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
			svc_restart_now(svc, serviced_kq);
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
		/*
		 * RC-unit backstop: the "onestop" command did not finish in
		 * time.  There is no meaningful process to SIGKILL — serviced's
		 * descriptor refers to the exited onestart wrapper, and the
		 * daemon reparented to init — so force the unit STOPPED rather
		 * than signal a dead descriptor, then run the shared post-stop
		 * handling.
		 */
		if (svc->rc_stopping) {
			syslog(LOG_WARNING, "rc unit %s: onestop timed out; "
			    "forcing stopped", svc->manifest.label);
			svc->rc_stopping = false;
			if (svc->pd_fd >= 0) {
				(void)close(svc->pd_fd);
				svc->pd_fd = -1;
			}
			svc->pid = 0;
			svc->state = SVC_STATE_STOPPED;
			supervisor_rc_post_stop(svc);
			return;
		}
		syslog(LOG_WARNING, "service %s: stop timeout, "
		    "sending SIGKILL", svc->manifest.label);
		if (svc->coalition_fd >= 0 &&
		    mac_cap_coalition_terminate(svc->coalition_fd) == -1)
			syslog(LOG_WARNING,
			    "service %s: coalition terminate: %m",
			    svc->manifest.label);
		/*
		 * Always SIGKILL the tracked process directly as well: the
		 * coalition sweep can miss a process that already left the
		 * coalition, and a coalition_terminate failure must never leave
		 * a service that ignored SIGTERM still running.
		 */
		if (svc->pd_fd >= 0)
			pdkill(svc->pd_fd, SIGKILL);
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
		svc_restart_now(svc, serviced_kq);
		return;
	}

	if (svc->idle_timer_ident != 0 && kev->ident == svc->idle_timer_ident) {
		svc->idle_timer_ident = 0;
		SERVICED_PROBE_TIMEOUT_FIRE(svc->manifest.label, "idle");
		/*
		 * Only a still-running provider is idle-stopped.  If it already
		 * left RUNNING for any other reason the expiry is moot.
		 */
		if (svc->state != SVC_STATE_RUNNING)
			return;
		syslog(LOG_INFO, "service %s: idle timeout, stopping "
		    "(reservations kept for on-demand relaunch)",
		    svc->manifest.label);
		svc->idle_stop_pending = true;
		svc_graceful_stop(svc, serviced_kq);
	}
}

/*
 * Stop an adopted RC unit by running "service <label> onestop".  An rc.d
 * daemon daemonizes and reparents to init, so the process descriptor serviced
 * holds refers to the long-exited "onestart" wrapper — signalling it (as the
 * native path does) never reaches the daemon and the unit wedges in STOPPING.
 * onestop instead reads the daemon's pidfile and signals the real process.
 *
 * This path deliberately skips the native teardown entirely: no quiesce
 * (there is no control channel), no coalition action, no pdkill.  It closes
 * the stale descriptor (auto-removing its NOTE_EXIT registration) so the fresh
 * descriptor svc_exec_rc_stop installs is the only one armed, marks the unit
 * STOPPING with rc_stopping set, and arms the stop-kill timer as a backstop
 * that force-stops the unit if onestop hangs (supervisor_handle_timer treats
 * an rc_stopping backstop as force-stop, not SIGKILL).  A launch failure is
 * best-effort: the unit is forced STOPPED rather than left wedged.
 */
static void
svc_rc_graceful_stop(struct svc_runtime *svc, int kq)
{

	svc->state = SVC_STATE_STOPPING;
	cancel_idle_timer(svc, kq);
	if (svc->pd_fd >= 0) {
		(void)close(svc->pd_fd);	/* EVFILT_PROCDESC auto-removed */
		svc->pd_fd = -1;
	}
	syslog(LOG_INFO, "rc unit %s: stopping via service onestop",
	    svc->manifest.label);
	SERVICED_PROBE_SVC_STOP(svc->manifest.label, svc->pid);
	if (svc_exec_rc_stop(svc, kq) == -1) {
		syslog(LOG_ERR, "rc unit %s: onestop launch failed; "
		    "forcing stopped", svc->manifest.label);
		svc->rc_stopping = false;
		svc->pid = 0;
		svc->state = SVC_STATE_STOPPED;
		supervisor_rc_post_stop(svc);
		return;
	}
	svc->rc_stopping = true;
	schedule_stop_kill(svc, kq);
}

/*
 * Gracefully stop a single service: SIGTERM via pdkill,
 * then kqueue timer-driven SIGKILL if still alive.
 */
void
svc_graceful_stop(struct svc_runtime *svc, int kq)
{
	struct svc_quiesce_msg message;

	if (svc->state != SVC_STATE_RUNNING &&
	    svc->state != SVC_STATE_STARTING)
		return;

	/*
	 * Adopted rc.d units cannot be stopped by signalling a process
	 * descriptor; they run their own onestop command.  Cleanly separated
	 * so the native/oneshot path below is untouched.
	 */
	if (svc->kind == SVC_KIND_RC) {
		svc_rc_graceful_stop(svc, kq);
		return;
	}

	svc->state = SVC_STATE_STOPPING;
	/*
	 * Once a stop is under way any pending idle timer is moot.  The
	 * idle-fire path clears idle_timer_ident before calling in here, so
	 * this is a no-op for an idle stop and preserves idle_stop_pending.
	 */
	cancel_idle_timer(svc, kq);
	syslog(LOG_INFO, "service %s: stopping (pid %jd)",
	    svc->manifest.label, (intmax_t)svc->pid);
	SERVICED_PROBE_SVC_STOP(svc->manifest.label, svc->pid);
	schedule_stop_kill(svc, kq);
	if (svc->protocol_ready && svc->control_channel != NULL) {
		memset(&message, 0, sizeof(message));
		message.op = SVC_OP_QUIESCE;
		message.reason = sd.shutting_down ? SVC_QUIESCE_REASON_SHUTDOWN :
		    (svc->reload_pending ? SVC_QUIESCE_REASON_RELOAD :
		    SVC_QUIESCE_REASON_STOP);
		message.deadline_ms = svc->manifest.stop_timeout * 1000;
		if (svc_channel_send_event(svc, &message, sizeof(message), NULL, 0,
		    kq) == 0) {
			svc->quiesce_pending = true;
			syslog(LOG_INFO, "service %s: quiesce requested "
			    "(reason %u deadline %ums)", svc->manifest.label,
			    message.reason, message.deadline_ms);
			SERVICED_PROBE_QUIESCE_REQUEST(svc->manifest.label,
			    message.reason, message.deadline_ms);
			return;
		}
		syslog(LOG_WARNING, "service %s: quiesce send failed: %m",
		    svc->manifest.label);
	} else
		syslog(LOG_INFO, "service %s: no quiesce channel "
		    "(protocol_ready=%d)", svc->manifest.label,
		    svc->protocol_ready);

	if (svc->coalition_fd >= 0) {
		if (mac_cap_coalition_graceful(svc->coalition_fd, SIGTERM,
		    (unsigned)svc->manifest.stop_timeout * 1000) == -1) {
			syslog(LOG_WARNING,
			    "service %s: coalition graceful: %m",
			    svc->manifest.label);
			if (svc->pd_fd >= 0)
				pdkill(svc->pd_fd, SIGTERM);
		}
	} else {
		if (svc->pd_fd >= 0)
			pdkill(svc->pd_fd, SIGTERM);
	}
}

void
svc_quiesce_complete(struct svc_runtime *svc, int status, int kq)
{

	if (svc == NULL || svc->state != SVC_STATE_STOPPING ||
	    !svc->quiesce_pending)
		return;
	svc->quiesce_pending = false;
	SERVICED_PROBE_QUIESCE_COMPLETE(svc->manifest.label, status);
	if (status != 0)
		syslog(LOG_WARNING, "service %s: quiesce completed with %s",
		    svc->manifest.label, strerror(status));
	if (svc->pd_fd >= 0)
		(void)pdkill(svc->pd_fd, SIGTERM);
	svc_channel_sync_events(svc, kq);
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
