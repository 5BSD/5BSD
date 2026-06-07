/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Hot-reload logic for serviced.
 *
 * Re-scans the manifest directory, diffs against running services,
 * and applies additions, changes, and removals with dependency
 * graph validation before mutating live state.
 */

#include <sys/event.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "serviced.h"
#include "serviced_probes.h"

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
	if (a->ncap_files != b->ncap_files)
		return (true);
	if (memcmp(a->cap_files, b->cap_files,
	    a->ncap_files * sizeof(a->cap_files[0])) != 0)
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
	if (a->ncap_jail != b->ncap_jail)
		return (true);
	if (memcmp(a->cap_jail, b->cap_jail,
	    a->ncap_jail * sizeof(a->cap_jail[0])) != 0)
		return (true);
	if (a->cap_system != b->cap_system)
		return (true);
	if (a->has_jail != b->has_jail)
		return (true);
	if (a->has_jail) {
		if (strcmp(a->jail_name, b->jail_name) != 0)
			return (true);
		if (strcmp(a->jail_path, b->jail_path) != 0)
			return (true);
		if (strcmp(a->jail_hostname, b->jail_hostname) != 0)
			return (true);
		if (strcmp(a->jail_ip4_addr, b->jail_ip4_addr) != 0)
			return (true);
	}
	if (a->stop_timeout != b->stop_timeout)
		return (true);
	if (a->max_failures != b->max_failures)
		return (true);
	return (false);
}

static bool
label_in(const char labels[][SERVICED_LABEL_MAX], unsigned nlabels,
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

	for (i = 0; i < sd.nservices; i++) {
		if (strcmp(sd.services[i].manifest.label, label) == 0)
			return (&sd.services[i]);
	}
	return (NULL);
}

/*
 * Remove a service from the array by index, shifting remaining
 * entries down.  Caller must re-register kevents afterward.
 */
void
svc_remove(unsigned idx)
{
	unsigned i;

	if (idx >= sd.nservices)
		return;

	for (i = idx; i < sd.nservices - 1; i++)
		sd.services[i] = sd.services[i + 1];

	sd.nservices--;

	/* Clear the vacated slot. */
	memset(&sd.services[sd.nservices], 0, sizeof(sd.services[0]));
	sd.services[sd.nservices].pd_fd = -1;
	sd.services[sd.nservices].pair_fd = -1;
	sd.services[sd.nservices].coalition_fd = -1;
	sd.services[sd.nservices].jail_fd = -1;
}

/*
 * Re-register kevent udata pointers for all running services.
 * Called after depgraph_sort moves array entries.
 */
void
svc_reregister_kevents(int kq)
{
	struct kevent kev;
	unsigned i;

	for (i = 0; i < sd.nservices; i++) {
		struct svc_runtime *svc = &sd.services[i];

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

static int
build_reload_candidate(struct svc_runtime *candidate, unsigned *ncandidate,
    const struct svc_manifest *disk, unsigned ndisk,
    const char new_labels[][SERVICED_LABEL_MAX], unsigned nnew,
    const char changed_labels[][SERVICED_LABEL_MAX], unsigned nchanged,
    const char removed_labels[][SERVICED_LABEL_MAX], unsigned nremoved)
{
	struct svc_runtime *svc;
	unsigned i, n;
	int di;

	memset(candidate, 0, SERVICED_MAX_SERVICES * sizeof(*candidate));
	n = 0;

	for (i = 0; i < sd.nservices; i++) {
		if (label_in(removed_labels, nremoved,
		    sd.services[i].manifest.label))
			continue;
		if (n >= SERVICED_MAX_SERVICES)
			return (-1);
		candidate[n] = sd.services[i];
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
		if (n >= SERVICED_MAX_SERVICES)
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

	if (sd.services == NULL) {
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
	for (i = 0; i < sd.nservices; i++) {
		if (strcmp(sd.services[i].manifest.label, m->label) == 0) {
			snprintf(summary, sumlen,
			    "error: service \"%s\" already loaded", m->label);
			free(m);
			return (-1);
		}
	}

	/* Check capacity. */
	if (sd.nservices >= SERVICED_MAX_SERVICES) {
		snprintf(summary, sumlen,
		    "error: service limit reached (%d)", SERVICED_MAX_SERVICES);
		free(m);
		return (-1);
	}

	/* Cancel pending restart timers before sort. */
	for (i = 0; i < sd.nservices; i++) {
		if (sd.services[i].restart_pending &&
		    sd.services[i].timer_ident != 0) {
			struct kevent kev;
			EV_SET(&kev, sd.services[i].timer_ident,
			    EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
			(void)kevent(kq, &kev, 1, NULL, 0, NULL);
			sd.services[i].timer_ident = 0;
		}
	}

	/* Add new service. */
	svc = &sd.services[sd.nservices];
	svc->manifest = *m;
	svc->pd_fd = -1;
	svc->pair_fd = -1;
	svc->coalition_fd = -1;
	svc->jail_fd = -1;
	svc->state = SVC_STATE_STOPPED;
	svc->restart_pending = false;
	sd.nservices++;

	syslog(LOG_INFO, "reload: new service \"%s\"", m->label);
	SERVICED_PROBE_SVC_LOAD(m->label);

	/* Re-sort dependencies. */
	if (depgraph_sort(sd.services, sd.nservices) == -1) {
		syslog(LOG_ERR, "reload: depgraph_sort failed after adding "
		    "\"%s\"", m->label);
		/* Roll back: remove the entry we just added. */
		sd.nservices--;
		memset(svc, 0, sizeof(*svc));
		svc->pd_fd = -1;
		svc->pair_fd = -1;
		svc->coalition_fd = -1;
		svc->jail_fd = -1;
		/* Re-sort the original set to restore order. */
		(void)depgraph_sort(sd.services, sd.nservices);
		svc_reregister_kevents(kq);
		snprintf(summary, sumlen,
		    "error: dependency cycle after adding \"%s\"", m->label);
		free(m);
		return (-1);
	}

	/* Re-register kevents for all services (sort moved entries). */
	svc_reregister_kevents(kq);

	/* Find and launch the new service (it moved during sort). */
	for (i = 0; i < sd.nservices; i++) {
		if (strcmp(sd.services[i].manifest.label, m->label) == 0) {
			svc = &sd.services[i];
			break;
		}
	}

	manifest_log(&svc->manifest);

	if (svc_exec(svc, kq) == -1) {
		snprintf(summary, sumlen,
		    "%s: loaded but failed to start",
		    m->label);
		free(m);
		return (-1);
	}

	snprintf(summary, sumlen,
	    "%s: validated OK\n%s: loaded, started (pid %jd)",
	    m->label, m->label, (intmax_t)svc->pid);

	free(m);
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
	char new_labels[SERVICED_MAX_SERVICES][SERVICED_LABEL_MAX];
	char changed_labels[SERVICED_MAX_SERVICES][SERVICED_LABEL_MAX];
	char removed_labels[SERVICED_MAX_SERVICES][SERVICED_LABEL_MAX];

	syslog(LOG_INFO, "reload: scanning %s", sd.manifest_dir);

	if (summary != NULL && sumlen > 0)
		summary[0] = '\0';
	candidate = NULL;

	if (sd.services == NULL) {
		syslog(LOG_WARNING, "reload: supervisor not initialized");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: supervisor not initialized\n");
		return (-1);
	}

	disk = calloc(SERVICED_MAX_SERVICES, sizeof(*disk));
	if (disk == NULL) {
		syslog(LOG_ERR, "reload: calloc: %m");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: out of memory\n");
		return (-1);
	}

	ndisk = 0;
	if (manifest_load_dir(sd.manifest_dir, disk,
	    SERVICED_MAX_SERVICES, &ndisk) == -1) {
		free(disk);
		return (-1);
	}

	nnew = nchanged = nremoved = 0;

	/* Phase 1: Identify new and changed manifests. */
	for (j = 0; j < ndisk; j++) {
		found = false;
		for (i = 0; i < sd.nservices; i++) {
			if (strcmp(sd.services[i].manifest.label,
			    disk[j].label) == 0) {
				found = true;
				if (manifest_changed(&sd.services[i].manifest,
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
					    SERVICED_LABEL_MAX);
					nchanged++;
				}
				break;
			}
		}
		if (!found) {
			char vbuf[256];

			if (sd.nservices >= SERVICED_MAX_SERVICES) {
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
			    SERVICED_LABEL_MAX);
			nnew++;
		}
	}

	/* Phase 2: Identify removed manifests. */
	for (i = 0; i < sd.nservices; i++) {
		found = false;
		for (j = 0; j < ndisk; j++) {
			if (strcmp(sd.services[i].manifest.label,
			    disk[j].label) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			strlcpy(removed_labels[nremoved],
			    sd.services[i].manifest.label,
			    SERVICED_LABEL_MAX);
			nremoved++;
		}
	}

	/* Phase 3: Validate the future graph before mutating live state. */
	if (nnew > 0 || nremoved > 0 || nchanged > 0) {
		candidate = calloc(SERVICED_MAX_SERVICES, sizeof(*candidate));
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
			free(candidate);
			free(disk);
			if (summary != NULL && sumlen > 0)
				snprintf(summary, sumlen,
				    "error: dependency graph rejected\n");
			return (-1);
		}

		/* Cancel pending restart timers before sort. */
		for (i = 0; i < sd.nservices; i++) {
			if (sd.services[i].restart_pending &&
			    sd.services[i].timer_ident != 0) {
				struct kevent kev;
				EV_SET(&kev, sd.services[i].timer_ident,
				    EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
				(void)kevent(kq, &kev, 1, NULL, 0, NULL);
				sd.services[i].timer_ident = 0;
			}
		}

		/* Append new services.  Existing live entries stay in place. */
		for (i = 0; i < nnew; i++) {
			int di;
			struct svc_runtime *svc;

			di = disk_index_by_label(disk, ndisk, new_labels[i]);
			if (di == -1 || sd.nservices >= SERVICED_MAX_SERVICES)
				continue;
			svc = &sd.services[sd.nservices++];
			memset(svc, 0, sizeof(*svc));
			svc->manifest = disk[di];
			svc->pd_fd = -1;
			svc->pair_fd = -1;
			svc->coalition_fd = -1;
			svc->state = SVC_STATE_STOPPED;
		}

		/* Stop changed services; NOTE_EXIT swaps manifests/restarts. */
		for (i = 0; i < sd.nservices; i++) {
			if (label_in(changed_labels, nchanged,
			    sd.services[i].manifest.label)) {
				int di;

				di = disk_index_by_label(disk, ndisk,
				    sd.services[i].manifest.label);
				if (di == -1)
					continue;
				syslog(LOG_INFO, "reload: restarting '%s' "
				    "(manifest changed)",
				    sd.services[i].manifest.label);
				SERVICED_PROBE_SVC_CHANGED(
				    sd.services[i].manifest.label);
				if (sd.services[i].state == SVC_STATE_STOPPED) {
					sd.services[i].manifest = disk[di];
					continue;
				}
				sd.services[i].pending_manifest = disk[di];
				sd.services[i].reload_pending = true;
				svc_graceful_stop(&sd.services[i], kq);
			}
		}

		/* Stop deleted services; NOTE_EXIT removes live entries. */
		for (i = sd.nservices; i > 0; i--) {
			if (label_in(removed_labels, nremoved,
			    sd.services[i - 1].manifest.label)) {
				syslog(LOG_INFO, "reload: removing '%s'",
				    sd.services[i - 1].manifest.label);
				SERVICED_PROBE_SVC_REMOVED(
				    sd.services[i - 1].manifest.label);
				if (sd.services[i - 1].state == SVC_STATE_STOPPED) {
					svc_remove(i - 1);
					continue;
				}
				sd.services[i - 1].remove_pending = true;
				svc_graceful_stop(&sd.services[i - 1], kq);
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
	SERVICED_PROBE_RELOAD(nnew, nchanged, nremoved);
	SERVICED_PROBE_SVC_COUNT(sd.nservices);

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
