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

/* Unique kevent ident offset for restart timers. */
#define	TIMER_IDENT_BASE	10000

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
schedule_restart(struct svc_runtime *svc, int kq, unsigned svc_index)
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

	EV_SET(&kev, TIMER_IDENT_BASE + svc_index, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, delay, svc);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_ERR, "service %s: kevent timer: %m",
		    svc->manifest.label);
}

/*
 * Find the index of a service in the global array.
 */
static int
svc_index(struct svc_runtime *svc)
{
	int idx;

	if (od.services == NULL)
		return (-1);
	idx = (int)(svc - od.services);
	if (idx < 0 || (unsigned)idx >= od.nservices)
		return (-1);
	return (idx);
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

	if (od.nservices == 0) {
		syslog(LOG_INFO, "supervisor: no services to start");
		free(manifests);
		return (0);
	}

	/* Allocate runtime state. */
	od.services = calloc(od.nservices, sizeof(*od.services));
	if (od.services == NULL) {
		syslog(LOG_ERR, "supervisor: calloc services: %m");
		free(manifests);
		od.nservices = 0;
		return (-1);
	}

	/* Copy manifests into runtime structs and initialize fds. */
	for (i = 0; i < od.nservices; i++) {
		od.services[i].manifest = manifests[i];
		od.services[i].pd_fd = -1;
		od.services[i].pair_fd = -1;
		od.services[i].coalition_fd = -1;
		od.services[i].state = SVC_STATE_STOPPED;
	}
	free(manifests);

	/* Topological sort. */
	if (depgraph_sort(od.services, od.nservices) == -1) {
		free(od.services);
		od.services = NULL;
		od.nservices = 0;
		return (-1);
	}

	/* Log service order. */
	for (i = 0; i < od.nservices; i++)
		manifest_log(&od.services[i].manifest);

	/* Launch services in dependency order. */
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
	int idx;

	svc = kev->udata;
	if (svc == NULL)
		return;

	if (kev->fflags & NOTE_EXEC) {
		svc->state = SVC_STATE_RUNNING;
		syslog(LOG_INFO, "service %s: exec confirmed (pid %jd)",
		    svc->manifest.label, (intmax_t)svc->pid);
		ORACLED_PROBE_SVC_EXEC(svc->manifest.label, svc->pid);
	}

	if (kev->fflags & NOTE_EXIT) {
		int was_stopping;

		svc->last_exit_status = (int)kev->data;
		clock_gettime(CLOCK_MONOTONIC, &svc->last_exit);

		if (WIFEXITED(svc->last_exit_status))
			syslog(LOG_INFO, "service %s: exited status %d "
			    "(pid %jd)", svc->manifest.label,
			    WEXITSTATUS(svc->last_exit_status),
			    (intmax_t)svc->pid);
		else if (WIFSIGNALED(svc->last_exit_status))
			syslog(LOG_INFO, "service %s: killed by signal %d "
			    "(pid %jd)", svc->manifest.label,
			    WTERMSIG(svc->last_exit_status),
			    (intmax_t)svc->pid);

		ORACLED_PROBE_SVC_EXIT(svc->manifest.label, svc->pid,
		    svc->last_exit_status);

		was_stopping = (svc->state == SVC_STATE_STOPPING);

		waitpid(svc->pid, NULL, WNOHANG);
		svc_close_fds(svc);
		svc->state = SVC_STATE_STOPPED;

		/* No restart if we asked it to stop. */
		if (was_stopping)
			return;

		idx = svc_index(svc);
		if (idx < 0)
			return;

		switch (svc->manifest.restart) {
		case SVC_RESTART_NEVER:
			return;
		case SVC_RESTART_ON_FAILURE:
			if (WIFEXITED(svc->last_exit_status) &&
			    WEXITSTATUS(svc->last_exit_status) == 0)
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

		/* Backoff if it died too fast. */
		if (uptime_sec < RESTART_MIN_UPTIME_SEC) {
			schedule_restart(svc, event_kq, (unsigned)idx);
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
	if (svc == NULL)
		return;

	if (kev->flags & EV_EOF) {
		syslog(LOG_INFO, "service %s: pair channel closed",
		    svc->manifest.label);
		return;
	}

	/*
	 * Agent sent a message on the pair channel.
	 * Future: handle oracle protocol messages.
	 * For now, drain and log.
	 */
	syslog(LOG_DEBUG, "service %s: pair channel activity",
	    svc->manifest.label);
}

void
supervisor_stop(int kq)
{
	unsigned i;

	if (od.services == NULL || od.nservices == 0)
		return;

	syslog(LOG_INFO, "supervisor: stopping %u services", od.nservices);

	/* Stop in reverse dependency order: graceful first. */
	for (i = od.nservices; i > 0; i--) {
		struct svc_runtime *svc = &od.services[i - 1];

		if (svc->state != SVC_STATE_RUNNING &&
		    svc->state != SVC_STATE_STARTING)
			continue;

		svc->state = SVC_STATE_STOPPING;
		syslog(LOG_INFO, "service %s: stopping (pid %jd)",
		    svc->manifest.label, (intmax_t)svc->pid);

		if (svc->coalition_fd >= 0)
			cap_rt_coalition_graceful(svc->coalition_fd,
			    SIGTERM, 5000);
		else if (svc->pd_fd >= 0)
			pdkill(svc->pd_fd, SIGTERM);
	}

	/* Brief pause for graceful shutdown. */
	usleep(500000);

	/* Forceful termination for anything still running. */
	for (i = od.nservices; i > 0; i--) {
		struct svc_runtime *svc = &od.services[i - 1];

		if (svc->state == SVC_STATE_STOPPED)
			continue;

		if (svc->coalition_fd >= 0)
			cap_rt_coalition_terminate(svc->coalition_fd);
		else if (svc->pd_fd >= 0)
			pdkill(svc->pd_fd, SIGKILL);

		if (svc->pid > 0)
			waitpid(svc->pid, NULL, 0);

		svc_close_fds(svc);
		svc->state = SVC_STATE_STOPPED;
	}

	free(od.services);
	od.services = NULL;
	od.nservices = 0;

	syslog(LOG_INFO, "supervisor: all services stopped");
	(void)kq;
}
