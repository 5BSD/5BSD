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

/* Monotonic counter for unique restart timer idents. */
static uintptr_t timer_next_ident = 10000;

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

	/* Allocate runtime state (fixed size to avoid realloc). */
	od.services = calloc(ORACLED_MAX_SERVICES, sizeof(*od.services));
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
	char drain[512];

	svc = kev->udata;
	if (svc == NULL)
		return;

	if (kev->flags & EV_EOF) {
		syslog(LOG_INFO, "service %s: pair channel closed",
		    svc->manifest.label);
		close(svc->pair_fd);
		svc->pair_fd = -1;
		return;
	}

	/*
	 * Agent sent a message on the pair channel.
	 * Future: handle oracle protocol messages.
	 * For now, drain and log to prevent busy-loop
	 * (kqueue is level-triggered for EVFILT_READ).
	 */
	(void)read(svc->pair_fd, drain, sizeof(drain));
	syslog(LOG_DEBUG, "service %s: pair channel activity",
	    svc->manifest.label);
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
		/* Re-schedule pending restart timers with new udata.
		 * The old timer was cancelled before the sort; create
		 * a fresh one with a 1-second minimum delay. */
		if (svc->restart_pending)
			schedule_restart(svc, kq);
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
	int off, rv;

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
 * brief pause, then SIGKILL if still alive.
 */
static void
svc_graceful_stop(struct svc_runtime *svc)
{

	if (svc->state != SVC_STATE_RUNNING &&
	    svc->state != SVC_STATE_STARTING)
		return;

	svc->state = SVC_STATE_STOPPING;
	syslog(LOG_INFO, "service %s: stopping (pid %jd)",
	    svc->manifest.label, (intmax_t)svc->pid);

	if (svc->coalition_fd >= 0)
		cap_rt_coalition_graceful(svc->coalition_fd,
		    SIGTERM, 5000);
	else if (svc->pd_fd >= 0)
		pdkill(svc->pd_fd, SIGTERM);

	usleep(500000);

	if (svc->state != SVC_STATE_STOPPED) {
		if (svc->coalition_fd >= 0)
			cap_rt_coalition_terminate(svc->coalition_fd);
		else if (svc->pd_fd >= 0)
			pdkill(svc->pd_fd, SIGKILL);

		if (svc->pid > 0)
			waitpid(svc->pid, NULL, WNOHANG);

		svc_close_fds(svc);
		svc->state = SVC_STATE_STOPPED;
	}
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
	unsigned ndisk, i, j;
	unsigned nnew, nchanged, nremoved;
	bool found;
	char new_labels[ORACLED_MAX_SERVICES][ORACLED_LABEL_MAX];
	char changed_labels[ORACLED_MAX_SERVICES][ORACLED_LABEL_MAX];
	unsigned changed_disk_idx[ORACLED_MAX_SERVICES];
	char removed_labels[ORACLED_MAX_SERVICES][ORACLED_LABEL_MAX];

	syslog(LOG_INFO, "reload: scanning %s", od.cfg.manifest_dir);
	ORACLED_PROBE_RELOAD();

	if (summary != NULL && sumlen > 0)
		summary[0] = '\0';

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
				if (memcmp(&od.services[i].manifest,
				    &disk[j],
				    sizeof(struct svc_manifest)) != 0) {
					strlcpy(changed_labels[nchanged],
					    disk[j].label,
					    ORACLED_LABEL_MAX);
					changed_disk_idx[nchanged] = j;
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
			od.services[od.nservices].manifest = disk[j];
			od.services[od.nservices].pd_fd = -1;
			od.services[od.nservices].pair_fd = -1;
			od.services[od.nservices].coalition_fd = -1;
			od.services[od.nservices].state = SVC_STATE_STOPPED;
			od.services[od.nservices].restart_pending = false;
			od.nservices++;
			ORACLED_PROBE_SVC_LOAD(disk[j].label);
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

	/* disk array is kept alive until Phase 5 uses changed_disk_idx. */

	/* Phase 3: Re-sort if any services added, removed, or changed. */
	if (nnew > 0 || nremoved > 0 || nchanged > 0) {
		/* Cancel pending restart timers before sort. */
		for (i = 0; i < od.nservices; i++) {
			if (od.services[i].restart_pending &&
			    od.services[i].timer_ident != 0) {
				struct kevent kev;
				EV_SET(&kev, od.services[i].timer_ident,
				    EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
				(void)kevent(kq, &kev, 1, NULL, 0, NULL);
			}
		}

		if (depgraph_sort(od.services, od.nservices) == -1) {
			syslog(LOG_ERR, "reload: depgraph_sort failed");
			ORACLED_PROBE_ERROR("reload", "depgraph_sort failed");
			/* Array is unsorted but services keep running. */
			svc_reregister_kevents(kq);
			return (-1);
		}
		svc_reregister_kevents(kq);
	}

	/* Phase 4: Start new services (in dependency order). */
	for (i = 0; i < od.nservices; i++) {
		unsigned k;
		for (k = 0; k < nnew; k++) {
			if (strcmp(od.services[i].manifest.label,
			    new_labels[k]) == 0) {
				syslog(LOG_INFO, "reload: starting '%s'",
				    new_labels[k]);
				svc_exec(&od.services[i], kq);
				break;
			}
		}
	}

	/* Phase 5: Stop changed services, swap manifest, restart. */
	for (i = 0; i < od.nservices; i++) {
		unsigned k;
		for (k = 0; k < nchanged; k++) {
			if (strcmp(od.services[i].manifest.label,
			    changed_labels[k]) == 0) {
				syslog(LOG_INFO, "reload: restarting '%s' "
				    "(manifest changed)",
				    changed_labels[k]);
				svc_graceful_stop(&od.services[i]);
				/* Now swap to the new manifest. */
				od.services[i].manifest =
				    disk[changed_disk_idx[k]];
				svc_exec(&od.services[i], kq);
				break;
			}
		}
	}

	/* Phase 6: Stop and remove deleted services (reverse order). */
	for (i = od.nservices; i > 0; i--) {
		unsigned k;
		for (k = 0; k < nremoved; k++) {
			if (strcmp(od.services[i - 1].manifest.label,
			    removed_labels[k]) == 0) {
				syslog(LOG_INFO, "reload: removing '%s'",
				    removed_labels[k]);
				svc_graceful_stop(&od.services[i - 1]);
				svc_remove(i - 1);
				/* Re-register after array shift. */
				svc_reregister_kevents(kq);
				break;
			}
		}
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

	/* Stop in reverse dependency order. */
	for (i = od.nservices; i > 0; i--)
		svc_graceful_stop(&od.services[i - 1]);

	free(od.services);
	od.services = NULL;
	od.nservices = 0;

	syslog(LOG_INFO, "supervisor: all services stopped");
	(void)kq;
}
