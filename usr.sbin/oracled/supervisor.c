/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service lifecycle supervisor for oracled.
 *
 * Orchestrates manifest loading, dependency sorting, service
 * startup, process lifecycle events, restart policy, and orderly
 * shutdown.  All operations integrate with the main kqueue loop.
 */

#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "oracled.h"
#include "probes.h"

/* Restart backoff parameters. */
#define	RESTART_MIN_UPTIME_SEC	5	/* rapid restart threshold */
#define	RESTART_MAX_DELAY_SEC	30
#define	RESTART_RESET_SEC	60	/* reset counter after stability */
#define	RESTART_MAX_FAILURES	5	/* circuit breaker threshold */
#define	RESTART_WINDOW_SEC	300	/* circuit breaker window (unused) */

/* Monotonic counters for unique timer idents.  High bit
 * distinguishes stop timers from restart timers. */
static uintptr_t timer_next_ident = 10000;
#define	STOP_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 1))
static uintptr_t stop_timer_next_ident = STOP_TIMER_BIT;

static void svc_remove(unsigned idx);
static void svc_reregister_kevents(int kq);

/*
 * Compare two manifests field-by-field, skipping label (used for
 * matching) and description (cosmetic).  Returns true if any
 * operationally significant field differs.
 */
static bool
manifest_changed(const struct svc_manifest *a, const struct svc_manifest *b)
{

	if (strcmp(a->program, b->program) != 0)
		return (true);
	if (strcmp(a->user, b->user) != 0)
		return (true);
	if (strcmp(a->group, b->group) != 0)
		return (true);
	if (a->restart != b->restart)
		return (true);
	if (a->ncap_paths != b->ncap_paths)
		return (true);
	if (memcmp(a->cap_paths, b->cap_paths,
	    a->ncap_paths * sizeof(a->cap_paths[0])) != 0)
		return (true);
	if (a->ncap_net != b->ncap_net)
		return (true);
	if (memcmp(a->cap_net, b->cap_net,
	    a->ncap_net * sizeof(a->cap_net[0])) != 0)
		return (true);
	if (a->nprovides != b->nprovides)
		return (true);
	if (memcmp(a->provides, b->provides,
	    a->nprovides * sizeof(a->provides[0])) != 0)
		return (true);
	if (a->nrequires != b->nrequires)
		return (true);
	if (memcmp(a->requires, b->requires,
	    a->nrequires * sizeof(a->requires[0])) != 0)
		return (true);
	if (a->cap_system != b->cap_system)
		return (true);
	if (a->stop_timeout != b->stop_timeout)
		return (true);
	return (false);
}

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
	if (svc->pair_fd >= 0) {
		close(svc->pair_fd);
		svc->pair_fd = -1;
	}
	if (svc->coalition_fd >= 0) {
		close(svc->coalition_fd);
		svc->coalition_fd = -1;
	}
}

/*
 * Schedule a delayed restart via EVFILT_TIMER on the kqueue.
 */
static void
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

	svc->timer_ident = timer_next_ident++;
	EV_SET(&kev, svc->timer_ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, delay, svc);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_ERR, "service %s: kevent timer: %m",
		    svc->manifest.label);
	else
		svc->restart_pending = true;
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
	else
		svc->stop_kill_pending = true;
}

static void
cancel_stop_timer(struct svc_runtime *svc)
{
	struct kevent kev;

	if (!svc->stop_kill_pending || svc->stop_timer_ident == 0)
		return;

	EV_SET(&kev, svc->stop_timer_ident, EVFILT_TIMER, EV_DELETE,
	    0, 0, NULL);
	(void)kevent(event_kq, &kev, 1, NULL, 0, NULL);
	svc->stop_kill_pending = false;
	svc->stop_timer_ident = 0;
}

int
supervisor_start(int kq)
{
	struct svc_manifest *manifests;
	unsigned i;

	manifests = calloc(ORACLED_MAX_SERVICES, sizeof(*manifests));
	if (manifests == NULL) {
		syslog(LOG_ERR, "supervisor: calloc manifests: %m");
		return (-1);
	}

	od.nservices = 0;
	if (manifest_load_dir(od.cfg.manifest_dir, manifests,
	    ORACLED_MAX_SERVICES, &od.nservices) == -1) {
		free(manifests);
		return (-1);
	}

	/* Allocate runtime state (fixed size to avoid realloc).
	 * Always allocate even with 0 services so reload can add. */
	od.services = calloc(ORACLED_MAX_SERVICES, sizeof(*od.services));
	if (od.services == NULL) {
		syslog(LOG_ERR, "supervisor: calloc services: %m");
		free(manifests);
		od.nservices = 0;
		return (-1);
	}

	if (od.nservices == 0)
		syslog(LOG_INFO, "supervisor: no services to start");

	for (i = 0; i < od.nservices; i++) {
		od.services[i].manifest = manifests[i];
		od.services[i].pd_fd = -1;
		od.services[i].pair_fd = -1;
		od.services[i].coalition_fd = -1;
		od.services[i].state = SVC_STATE_STOPPED;
	}
	free(manifests);

	if (depgraph_sort(od.services, od.nservices) == -1) {
		/*
		 * Keep the runtime array allocated so a later reload can
		 * recover after the manifest set is fixed.
		 */
		od.nservices = 0;
		return (-1);
	}

	for (i = 0; i < od.nservices; i++)
		manifest_log(&od.services[i].manifest);

	for (i = 0; i < od.nservices; i++) {
		if (svc_exec(&od.services[i], kq) == -1)
			syslog(LOG_WARNING, "supervisor: failed to start %s",
			    od.services[i].manifest.label);
	}

	syslog(LOG_INFO, "supervisor: %u services launched", od.nservices);
	return (0);
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
		svc->state = SVC_STATE_RUNNING;
		syslog(LOG_INFO, "service %s: exec confirmed (pid %jd)",
		    svc->manifest.label, (intmax_t)svc->pid);
		ORACLED_PROBE_SVC_EXEC(svc->manifest.label, svc->pid);
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

		ORACLED_PROBE_SVC_EXIT(svc->manifest.label, svc->pid,
		    exit_status);

		was_stopping = (svc->state == SVC_STATE_STOPPING);
		reload_pending = svc->reload_pending;
		remove_pending = svc->remove_pending;

		waitpid(svc->pid, NULL, WNOHANG);
		cancel_stop_timer(svc);
		svc_close_fds(svc);
		svc->state = SVC_STATE_STOPPED;

		if (was_stopping && remove_pending) {
			unsigned idx;

			idx = (unsigned)(svc - od.services);
			svc_remove(idx);
			svc_reregister_kevents(event_kq);
			return;
		}

		if (was_stopping && reload_pending) {
			svc->manifest = svc->pending_manifest;
			memset(&svc->pending_manifest, 0,
			    sizeof(svc->pending_manifest));
			svc->reload_pending = false;
			svc_exec(svc, event_kq);
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
		ORACLED_PROBE_SVC_RESTART(svc->manifest.label,
		    svc->restart_count);

		/* Reset counter if the service ran for a while. */
		clock_gettime(CLOCK_MONOTONIC, &now);
		uptime_sec = now.tv_sec - svc->last_start.tv_sec;
		if (uptime_sec >= RESTART_RESET_SEC)
			svc->restart_count = 1;

		/* Circuit breaker: disable service after too many failures. */
		if (svc->restart_count >= RESTART_MAX_FAILURES) {
			syslog(LOG_CRIT, "service %s: failed %u times, "
			    "disabling", svc->manifest.label,
			    svc->restart_count);
			svc->state = SVC_STATE_STOPPED;
			return;
		}

		/* Backoff if it died too fast. */
		if (uptime_sec < RESTART_MIN_UPTIME_SEC) {
			schedule_restart(svc, event_kq);
		} else {
			syslog(LOG_INFO, "service %s: restarting "
			    "(count %u)", svc->manifest.label,
			    svc->restart_count);
			svc_exec(svc, event_kq);
		}
	}
}

void
supervisor_handle_pair(struct kevent *kev)
{
	struct svc_runtime *svc;

	svc = kev->udata;

	if ((int)kev->ident == svc->coalition_fd) {
		uint32_t flags;
		int rv;

		do {
			rv = cap_rt_coalition_recv_event(svc->coalition_fd,
			    &flags);
			if (rv == 0)
				syslog(LOG_DEBUG, "service %s: coalition "
				    "event flags=0x%x", svc->manifest.label,
				    flags);
			else if (rv == -1)
				syslog(LOG_WARNING, "service %s: coalition "
				    "event receive: %m", svc->manifest.label);
		} while (rv == 0);
		return;
	}

	if (kev->flags & EV_EOF) {
		syslog(LOG_INFO, "service %s: pair channel closed",
		    svc->manifest.label);
		close(svc->pair_fd);
		svc->pair_fd = -1;
		return;
	}

	/*
	 * The pair channel exists for future oracle protocol use
	 * but is not currently read.  Disable the kqueue filter to
	 * avoid a busy-loop (EVFILT_READ is level-triggered).
	 */
	{
		struct kevent disable_kev;
		EV_SET(&disable_kev, svc->pair_fd, EVFILT_READ, EV_DISABLE, 0, 0, svc);
		(void)kevent(event_kq, &disable_kev, 1, NULL, 0, NULL);
	}
	syslog(LOG_DEBUG, "service %s: pair channel activity (disabled)",
	    svc->manifest.label);
}

void
supervisor_handle_timer(struct kevent *kev)
{
	struct svc_runtime *svc;

	svc = kev->udata;

	if (svc->stop_kill_pending && kev->ident == svc->stop_timer_ident) {
		svc->stop_kill_pending = false;
		svc->stop_timer_ident = 0;
		syslog(LOG_WARNING, "service %s: stop timeout, "
		    "sending SIGKILL", svc->manifest.label);
		if (svc->coalition_fd >= 0)
			cap_rt_coalition_terminate(svc->coalition_fd);
		else if (svc->pd_fd >= 0)
			pdkill(svc->pd_fd, SIGKILL);
		return;
	}

	if (svc->restart_pending && kev->ident == svc->timer_ident) {
		svc->restart_pending = false;
		svc->timer_ident = 0;
		if (od.shutting_down) {
			syslog(LOG_INFO, "service %s: restart cancelled "
			    "(shutting down)", svc->manifest.label);
			return;
		}
		syslog(LOG_INFO, "service %s: restart timer fired",
		    svc->manifest.label);
		svc_exec(svc, event_kq);
	}
}

/*
 * Re-register kevent udata pointers for all running services.
 * Called after depgraph_sort moves array entries.
 */
static void
svc_reregister_kevents(int kq)
{
	struct kevent kev;
	unsigned i;

	for (i = 0; i < od.nservices; i++) {
		struct svc_runtime *svc = &od.services[i];

		if (svc->state == SVC_STATE_STOPPED &&
		    !svc->restart_pending)
			continue;

		if (svc->pd_fd >= 0) {
			EV_SET(&kev, svc->pd_fd, EVFILT_PROCDESC,
			    EV_ADD, NOTE_EXIT | NOTE_EXEC, 0, svc);
			if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
				syslog(LOG_WARNING,
				    "reload: re-register pd_fd for %s: %m",
				    svc->manifest.label);
		}
		if (svc->pair_fd >= 0) {
			EV_SET(&kev, svc->pair_fd, EVFILT_READ,
			    EV_ADD, 0, 0, svc);
			if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
				syslog(LOG_WARNING,
				    "reload: re-register pair_fd for %s: %m",
				    svc->manifest.label);
		}
		if (svc->coalition_fd >= 0) {
			EV_SET(&kev, svc->coalition_fd, EVFILT_READ,
			    EV_ADD, 0, 0, svc);
			if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
				syslog(LOG_WARNING,
				    "reload: re-register coalition_fd "
				    "for %s: %m", svc->manifest.label);
		}
		/* Re-schedule pending restart timers with new udata.
		 * The old timer was cancelled before the sort; create
		 * a fresh one with a 1-second minimum delay. */
		if (svc->restart_pending)
			schedule_restart(svc, kq);
		/* Update stop-kill timer udata if active. */
		if (svc->stop_kill_pending && svc->stop_timer_ident != 0) {
			EV_SET(&kev, svc->stop_timer_ident, EVFILT_TIMER,
			    EV_ADD | EV_ONESHOT, NOTE_SECONDS, 5, svc);
			(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		}
	}
}

/*
 * Validate a manifest file without loading it.
 * Writes a human-readable summary into summary/sumlen.
 * Returns 0 on success, -1 on error (summary contains the error).
 */
int
supervisor_check_manifest(const char *path, char *summary, size_t sumlen)
{
	struct svc_manifest *m;
	char errbuf[256];
	int off;

	m = calloc(1, sizeof(*m));
	if (m == NULL) {
		snprintf(summary, sumlen, "error: out of memory");
		return (-1);
	}

	if (manifest_load_file(path, m) == -1) {
		snprintf(summary, sumlen, "error: failed to parse %s", path);
		free(m);
		return (-1);
	}

	if (manifest_validate(m, errbuf, sizeof(errbuf)) == -1) {
		snprintf(summary, sumlen, "error: %s", errbuf);
		free(m);
		return (-1);
	}

	off = manifest_format_summary(m, summary, sumlen);
	if ((size_t)off < sumlen)
		snprintf(summary + off, sumlen - off,
		    "  status:       OK (dry run)\n");
	free(m);
	return (0);
}

/*
 * Load a single manifest file, add it to the services array,
 * sort dependencies, and launch the new service.
 * Writes result into summary/sumlen.
 * Returns 0 on success, -1 on error.
 */
int
supervisor_load_manifest(const char *path, int kq,
    char *summary, size_t sumlen)
{
	struct svc_manifest *m;
	struct svc_runtime *svc;
	char errbuf[256];
	unsigned i;

	if (od.services == NULL) {
		snprintf(summary, sumlen, "error: supervisor not initialized");
		return (-1);
	}

	m = calloc(1, sizeof(*m));
	if (m == NULL) {
		snprintf(summary, sumlen, "error: out of memory");
		return (-1);
	}

	/* Parse. */
	if (manifest_load_file(path, m) == -1) {
		snprintf(summary, sumlen, "error: failed to parse %s", path);
		free(m);
		return (-1);
	}

	/* Validate. */
	if (manifest_validate(m, errbuf, sizeof(errbuf)) == -1) {
		snprintf(summary, sumlen, "error: %s", errbuf);
		free(m);
		return (-1);
	}

	/* Check for duplicate label. */
	for (i = 0; i < od.nservices; i++) {
		if (strcmp(od.services[i].manifest.label, m->label) == 0) {
			snprintf(summary, sumlen,
			    "error: service \"%s\" already loaded", m->label);
			free(m);
			return (-1);
		}
	}

	/* Check capacity. */
	if (od.nservices >= ORACLED_MAX_SERVICES) {
		snprintf(summary, sumlen,
		    "error: service limit reached (%d)", ORACLED_MAX_SERVICES);
		free(m);
		return (-1);
	}

	/* Cancel pending restart timers before sort. */
	for (i = 0; i < od.nservices; i++) {
		if (od.services[i].restart_pending &&
		    od.services[i].timer_ident != 0) {
			struct kevent kev;
			EV_SET(&kev, od.services[i].timer_ident,
			    EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
			(void)kevent(kq, &kev, 1, NULL, 0, NULL);
			od.services[i].timer_ident = 0;
		}
	}

	/* Add new service. */
	svc = &od.services[od.nservices];
	svc->manifest = *m;
	svc->pd_fd = -1;
	svc->pair_fd = -1;
	svc->coalition_fd = -1;
	svc->state = SVC_STATE_STOPPED;
	svc->restart_pending = false;
	od.nservices++;

	syslog(LOG_INFO, "reload: new service \"%s\"", m->label);
	ORACLED_PROBE_SVC_LOAD(m->label);

	/* Re-sort dependencies. */
	if (depgraph_sort(od.services, od.nservices) == -1) {
		syslog(LOG_ERR, "reload: depgraph_sort failed after adding "
		    "\"%s\"", m->label);
		ORACLED_PROBE_ERROR("load", "depgraph_sort failed");
		/* Roll back: remove the entry we just added. */
		od.nservices--;
		memset(svc, 0, sizeof(*svc));
		svc->pd_fd = -1;
		svc->pair_fd = -1;
		svc->coalition_fd = -1;
		/* Re-sort the original set to restore order. */
		(void)depgraph_sort(od.services, od.nservices);
		svc_reregister_kevents(kq);
		snprintf(summary, sumlen,
		    "error: dependency cycle after adding \"%s\"", m->label);
		free(m);
		return (-1);
	}

	/* Re-register kevents for all services (sort moved entries). */
	svc_reregister_kevents(kq);

	/* Find and launch the new service (it moved during sort). */
	for (i = 0; i < od.nservices; i++) {
		if (strcmp(od.services[i].manifest.label, m->label) == 0) {
			svc = &od.services[i];
			break;
		}
	}

	manifest_log(&svc->manifest);

	if (svc_exec(svc, kq) == -1) {
		snprintf(summary, sumlen,
		    "%s: validated OK\n%s: loaded, failed to start",
		    m->label, m->label);
		free(m);
		return (0);	/* loaded successfully, just didn't start */
	}

	snprintf(summary, sumlen,
	    "%s: validated OK\n%s: loaded, started (pid %jd)",
	    m->label, m->label, (intmax_t)svc->pid);

	ORACLED_PROBE_SVC_START(m->label, svc->pid);
	free(m);
	return (0);
}

/*
 * Gracefully stop a single service: SIGTERM via coalition (or pdkill),
 * then kqueue timer-driven SIGKILL if still alive.
 */
static void
svc_graceful_stop(struct svc_runtime *svc, int kq)
{

	if (svc->state != SVC_STATE_RUNNING &&
	    svc->state != SVC_STATE_STARTING)
		return;

	svc->state = SVC_STATE_STOPPING;
	syslog(LOG_INFO, "service %s: stopping (pid %jd)",
	    svc->manifest.label, (intmax_t)svc->pid);

	if (svc->coalition_fd >= 0) {
		/* Send SIGTERM immediately (1ms deadline), escalate
		 * to coalition-level kill after 5s grace period. */
		if (cap_rt_coalition_set_deadline(svc->coalition_fd,
		    1, SIGTERM, 5000) != 0)
			syslog(LOG_WARNING, "service %s: coalition "
			    "deadline: %m", svc->manifest.label);
	} else if (svc->pd_fd >= 0)
		pdkill(svc->pd_fd, SIGTERM);
	schedule_stop_kill(svc, kq);
}

/*
 * Remove a service from the array by index, shifting remaining
 * entries down.  Caller must re-register kevents afterward.
 */
static void
svc_remove(unsigned idx)
{
	unsigned i;

	if (idx >= od.nservices)
		return;

	for (i = idx; i < od.nservices - 1; i++)
		od.services[i] = od.services[i + 1];

	od.nservices--;

	/* Clear the vacated slot. */
	memset(&od.services[od.nservices], 0, sizeof(od.services[0]));
	od.services[od.nservices].pd_fd = -1;
	od.services[od.nservices].pair_fd = -1;
	od.services[od.nservices].coalition_fd = -1;
}

static bool
label_in(const char labels[][ORACLED_LABEL_MAX], unsigned nlabels,
    const char *label)
{
	unsigned i;

	for (i = 0; i < nlabels; i++) {
		if (strcmp(labels[i], label) == 0)
			return (true);
	}
	return (false);
}

static int
disk_index_by_label(const struct svc_manifest *disk, unsigned ndisk,
    const char *label)
{
	unsigned i;

	for (i = 0; i < ndisk; i++) {
		if (strcmp(disk[i].label, label) == 0)
			return ((int)i);
	}
	return (-1);
}

static struct svc_runtime *
svc_by_label(const char *label)
{
	unsigned i;

	for (i = 0; i < od.nservices; i++) {
		if (strcmp(od.services[i].manifest.label, label) == 0)
			return (&od.services[i]);
	}
	return (NULL);
}

static int
build_reload_candidate(struct svc_runtime *candidate, unsigned *ncandidate,
    const struct svc_manifest *disk, unsigned ndisk,
    const char new_labels[][ORACLED_LABEL_MAX], unsigned nnew,
    const char changed_labels[][ORACLED_LABEL_MAX], unsigned nchanged,
    const char removed_labels[][ORACLED_LABEL_MAX], unsigned nremoved)
{
	struct svc_runtime *svc;
	unsigned i, n;
	int di;

	memset(candidate, 0, ORACLED_MAX_SERVICES * sizeof(*candidate));
	n = 0;

	for (i = 0; i < od.nservices; i++) {
		if (label_in(removed_labels, nremoved,
		    od.services[i].manifest.label))
			continue;
		if (n >= ORACLED_MAX_SERVICES)
			return (-1);
		candidate[n] = od.services[i];
		if (label_in(changed_labels, nchanged,
		    candidate[n].manifest.label)) {
			di = disk_index_by_label(disk, ndisk,
			    candidate[n].manifest.label);
			if (di == -1)
				return (-1);
			candidate[n].manifest = disk[di];
		}
		n++;
	}

	for (i = 0; i < nnew; i++) {
		if (n >= ORACLED_MAX_SERVICES)
			return (-1);
		di = disk_index_by_label(disk, ndisk, new_labels[i]);
		if (di == -1)
			return (-1);
		svc = &candidate[n];
		svc->manifest = disk[di];
		svc->pd_fd = -1;
		svc->pair_fd = -1;
		svc->coalition_fd = -1;
		svc->state = SVC_STATE_STOPPED;
		n++;
	}

	if (depgraph_sort(candidate, n) == -1)
		return (-1);

	*ncandidate = n;
	return (0);
}

/*
 * Reload: re-scan the manifest directory and diff against running
 * services.  Add new, restart changed, remove deleted.
 *
 * Order: add new services first, then restart changed, then
 * stop removed.  This ensures dependencies are satisfied before
 * dependents lose their providers.
 */
int
supervisor_reload(int kq, char *summary, size_t sumlen)
{
	struct svc_manifest *disk;
	struct svc_runtime *candidate;
	unsigned ndisk, ncandidate, i, j;
	unsigned nnew, nchanged, nremoved;
	bool found;
	char new_labels[ORACLED_MAX_SERVICES][ORACLED_LABEL_MAX];
	char changed_labels[ORACLED_MAX_SERVICES][ORACLED_LABEL_MAX];
	char removed_labels[ORACLED_MAX_SERVICES][ORACLED_LABEL_MAX];

	syslog(LOG_INFO, "reload: scanning %s", od.cfg.manifest_dir);
	ORACLED_PROBE_RELOAD();

	if (summary != NULL && sumlen > 0)
		summary[0] = '\0';
	candidate = NULL;

	if (od.services == NULL) {
		syslog(LOG_WARNING, "reload: supervisor not initialized");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: supervisor not initialized\n");
		return (-1);
	}

	disk = calloc(ORACLED_MAX_SERVICES, sizeof(*disk));
	if (disk == NULL) {
		syslog(LOG_ERR, "reload: calloc: %m");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: out of memory\n");
		return (-1);
	}

	ndisk = 0;
	if (manifest_load_dir(od.cfg.manifest_dir, disk,
	    ORACLED_MAX_SERVICES, &ndisk) == -1) {
		free(disk);
		return (-1);
	}

	nnew = nchanged = nremoved = 0;

	/* Phase 1: Identify new and changed manifests. */
	for (j = 0; j < ndisk; j++) {
		found = false;
		for (i = 0; i < od.nservices; i++) {
			if (strcmp(od.services[i].manifest.label,
			    disk[j].label) == 0) {
				found = true;
				if (manifest_changed(&od.services[i].manifest,
				    &disk[j])) {
					char vbuf[256];

					if (manifest_validate(&disk[j], vbuf,
					    sizeof(vbuf)) == -1) {
						syslog(LOG_WARNING,
						    "reload: rejecting "
						    "changed '%s': %s",
						    disk[j].label, vbuf);
						break;
					}
					strlcpy(changed_labels[nchanged],
					    disk[j].label,
					    ORACLED_LABEL_MAX);
					nchanged++;
				}
				break;
			}
		}
		if (!found) {
			char vbuf[256];

			if (od.nservices >= ORACLED_MAX_SERVICES) {
				syslog(LOG_WARNING, "reload: cannot add "
				    "'%s': limit reached", disk[j].label);
				continue;
			}
			if (manifest_validate(&disk[j], vbuf,
			    sizeof(vbuf)) == -1) {
				syslog(LOG_WARNING, "reload: rejecting "
				    "'%s': %s", disk[j].label, vbuf);
				continue;
			}
			strlcpy(new_labels[nnew], disk[j].label,
			    ORACLED_LABEL_MAX);
			nnew++;
		}
	}

	/* Phase 2: Identify removed manifests. */
	for (i = 0; i < od.nservices; i++) {
		found = false;
		for (j = 0; j < ndisk; j++) {
			if (strcmp(od.services[i].manifest.label,
			    disk[j].label) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			strlcpy(removed_labels[nremoved],
			    od.services[i].manifest.label,
			    ORACLED_LABEL_MAX);
			nremoved++;
		}
	}

	/* Phase 3: Validate the future graph before mutating live state. */
	if (nnew > 0 || nremoved > 0 || nchanged > 0) {
		candidate = calloc(ORACLED_MAX_SERVICES, sizeof(*candidate));
		if (candidate == NULL) {
			syslog(LOG_ERR, "reload: calloc candidate: %m");
			free(disk);
			if (summary != NULL && sumlen > 0)
				snprintf(summary, sumlen,
				    "error: out of memory\n");
			return (-1);
		}

		ncandidate = 0;
		if (build_reload_candidate(candidate, &ncandidate, disk,
		    ndisk, new_labels, nnew, changed_labels, nchanged,
		    removed_labels, nremoved) == -1) {
			syslog(LOG_ERR, "reload: depgraph_sort failed");
			ORACLED_PROBE_ERROR("reload", "depgraph_sort failed");
			free(candidate);
			free(disk);
			if (summary != NULL && sumlen > 0)
				snprintf(summary, sumlen,
				    "error: dependency graph rejected\n");
			return (-1);
		}

		/* Cancel pending restart timers before sort. */
		for (i = 0; i < od.nservices; i++) {
			if (od.services[i].restart_pending &&
			    od.services[i].timer_ident != 0) {
				struct kevent kev;
				EV_SET(&kev, od.services[i].timer_ident,
				    EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
				(void)kevent(kq, &kev, 1, NULL, 0, NULL);
				od.services[i].timer_ident = 0;
			}
		}

		/* Append new services.  Existing live entries stay in place. */
		for (i = 0; i < nnew; i++) {
			int di;
			struct svc_runtime *svc;

			di = disk_index_by_label(disk, ndisk, new_labels[i]);
			if (di == -1 || od.nservices >= ORACLED_MAX_SERVICES)
				continue;
			svc = &od.services[od.nservices++];
			memset(svc, 0, sizeof(*svc));
			svc->manifest = disk[di];
			svc->pd_fd = -1;
			svc->pair_fd = -1;
			svc->coalition_fd = -1;
			svc->state = SVC_STATE_STOPPED;
			ORACLED_PROBE_SVC_LOAD(svc->manifest.label);
		}

		/* Stop changed services; NOTE_EXIT swaps manifests/restarts. */
		for (i = 0; i < od.nservices; i++) {
			if (label_in(changed_labels, nchanged,
			    od.services[i].manifest.label)) {
				int di;

				di = disk_index_by_label(disk, ndisk,
				    od.services[i].manifest.label);
				if (di == -1)
					continue;
				syslog(LOG_INFO, "reload: restarting '%s' "
				    "(manifest changed)",
				    od.services[i].manifest.label);
				if (od.services[i].state == SVC_STATE_STOPPED) {
					od.services[i].manifest = disk[di];
					continue;
				}
				od.services[i].pending_manifest = disk[di];
				od.services[i].reload_pending = true;
				svc_graceful_stop(&od.services[i], kq);
			}
		}

		/* Stop deleted services; NOTE_EXIT removes live entries. */
		for (i = od.nservices; i > 0; i--) {
			if (label_in(removed_labels, nremoved,
			    od.services[i - 1].manifest.label)) {
				syslog(LOG_INFO, "reload: removing '%s'",
				    od.services[i - 1].manifest.label);
				if (od.services[i - 1].state == SVC_STATE_STOPPED) {
					svc_remove(i - 1);
					continue;
				}
				od.services[i - 1].remove_pending = true;
				svc_graceful_stop(&od.services[i - 1], kq);
			}
		}
		svc_reregister_kevents(kq);
	}

	/* Phase 4: Start new services in validated dependency order. */
	if (candidate != NULL) {
		for (i = 0; i < ncandidate; i++) {
			struct svc_runtime *svc;

			if (!label_in(new_labels, nnew,
			    candidate[i].manifest.label))
				continue;
			svc = svc_by_label(candidate[i].manifest.label);
			if (svc != NULL && svc->state == SVC_STATE_STOPPED) {
				syslog(LOG_INFO, "reload: starting '%s'",
				    svc->manifest.label);
				svc_exec(svc, kq);
			}
		}
		free(candidate);
	}

	free(disk);

	syslog(LOG_INFO, "reload: %u new, %u changed, %u removed",
	    nnew, nchanged, nremoved);

	if (summary != NULL && sumlen > 0) {
		size_t off = 0;

		for (i = 0; i < nnew; i++)
			BUF_APPEND(summary, sumlen, &off,
			    "  added:    %s\n", new_labels[i]);
		for (i = 0; i < nchanged; i++)
			BUF_APPEND(summary, sumlen, &off,
			    "  changed:  %s\n", changed_labels[i]);
		for (i = 0; i < nremoved; i++)
			BUF_APPEND(summary, sumlen, &off,
			    "  removed:  %s\n", removed_labels[i]);
		BUF_APPEND(summary, sumlen, &off,
		    "reload: %u new, %u changed, %u removed\n",
		    nnew, nchanged, nremoved);
	}

	return (0);
}

void
supervisor_stop(int kq)
{
	unsigned i;

	if (od.services == NULL || od.nservices == 0)
		return;

	syslog(LOG_INFO, "supervisor: stopping %u services", od.nservices);

	/* Stop in reverse dependency order.  Services that are already
	 * stopped or waiting for a restart timer are removed immediately.
	 * Running services get graceful stop + remove on NOTE_EXIT. */
	for (i = od.nservices; i > 0; i--) {
		struct svc_runtime *svc = &od.services[i - 1];

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

	return (od.services == NULL || od.nservices == 0);
}

void
supervisor_teardown_state(void)
{

	free(od.services);
	od.services = NULL;
	od.nservices = 0;
	syslog(LOG_INFO, "supervisor: all services stopped");
}
