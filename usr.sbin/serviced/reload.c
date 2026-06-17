/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Hot-reload logic for serviced.
 *
 * Re-scans bundle directories, diffs against running services,
 * and applies additions and removals.
 */

#include <sys/event.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <libcapbundle.h>

#include "serviced.h"
#include "serviced_probes.h"

struct svc_runtime *
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

	for (i = idx; i < sd.nservices - 1; i++) {
		sd.services[i] = sd.services[i + 1];
		naming_rebind_owner(&sd.services[i + 1], &sd.services[i]);
	}

	sd.nservices--;

	/* Clear the vacated slot. */
	memset(&sd.services[sd.nservices], 0, sizeof(sd.services[0]));
	sd.services[sd.nservices].pd_fd = -1;
	sd.services[sd.nservices].channel_fd = -1;
	sd.services[sd.nservices].coalition_fd = -1;
	sd.services[sd.nservices].jail_fd = -1;
}

static bool
manifest_equal(const struct svc_manifest *a, const struct svc_manifest *b)
{

	if (strcmp(a->label, b->label) != 0 ||
	    strcmp(a->program, b->program) != 0 ||
	    strcmp(a->user, b->user) != 0 ||
	    strcmp(a->group, b->group) != 0 ||
	    a->restart != b->restart ||
	    a->stop_timeout != b->stop_timeout ||
	    a->max_failures != b->max_failures ||
	    a->on_demand != b->on_demand ||
	    a->nprovides != b->nprovides ||
	    a->nrequires != b->nrequires ||
	    a->ncap_paths != b->ncap_paths ||
	    a->ncap_net != b->ncap_net ||
	    a->ncap_files != b->ncap_files ||
	    a->ncap_jail != b->ncap_jail ||
	    a->cap_system != b->cap_system ||
	    a->has_jail != b->has_jail)
		return (false);
	if (a->has_jail &&
	    (strcmp(a->jail_name, b->jail_name) != 0 ||
	    strcmp(a->jail_path, b->jail_path) != 0 ||
	    strcmp(a->jail_hostname, b->jail_hostname) != 0 ||
	    strcmp(a->jail_ip4_addr, b->jail_ip4_addr) != 0))
		return (false);
	return (memcmp(a->provides, b->provides,
	    sizeof(a->provides)) == 0 &&
	    memcmp(a->requires, b->requires,
	    sizeof(a->requires)) == 0 &&
	    memcmp(a->cap_paths, b->cap_paths,
	    sizeof(a->cap_paths)) == 0 &&
	    memcmp(a->cap_net, b->cap_net,
	    sizeof(a->cap_net)) == 0 &&
	    memcmp(a->cap_files, b->cap_files,
	    sizeof(a->cap_files)) == 0 &&
	    memcmp(a->cap_jail, b->cap_jail,
	    sizeof(a->cap_jail)) == 0);
}

static bool
bundle_service_manifest(const char *label, struct svc_manifest *m)
{
	unsigned bi, si;
	struct capbundle *ab;
	struct capbundle_service *asvc;

	/*
	 * Search by label, not by provides name.  bundle_registry_lookup
	 * searches the provides hash, which only works when label ==
	 * provides[0].  Fall back to a linear scan to find services whose
	 * label differs from their provides names.
	 */
	if (bundle_registry_lookup(label, &bi, &si) == 0) {
		ab = bundle_registry_get(bi);
		if (ab != NULL) {
			asvc = capbundle_service(ab, si);
			if (asvc != NULL &&
			    strcmp(capbundle_svc_label(asvc), label) == 0)
				return (capbundle_svc_fill_manifest(asvc,
				    m) == 0);
		}
	}

	/* Linear scan: label may differ from provides names. */
	for (bi = 0; bi < bundle_registry_count(); bi++) {
		ab = bundle_registry_get(bi);
		if (ab == NULL)
			continue;
		for (si = 0; si < capbundle_nservices(ab); si++) {
			asvc = capbundle_service(ab, si);
			if (asvc == NULL)
				continue;
			if (strcmp(capbundle_svc_label(asvc), label) == 0)
				return (capbundle_svc_fill_manifest(asvc,
				    m) == 0);
		}
	}
	return (false);
}

static bool
desired_service_manifest(const char *label, struct svc_manifest *m)
{
	return (bundle_service_manifest(label, m));
}

/*
 * Re-register kevent udata pointers for all running services.
 * Called after svc_remove() shifts array entries (Phase 1) or
 * after depgraph_sort() reorders entries (Phase 3).
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
		if (svc->channel_fd >= 0) {
			EV_SET(&kev, svc->channel_fd, EVFILT_READ,
			    EV_ADD, 0, 0, svc);
			if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
				syslog(LOG_WARNING,
				    "reload: re-register channel_fd for %s: %m",
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
 * Reload: re-scan bundle directories and diff against running services.
 * Add new services, stop removed ones.
 */
int
supervisor_reload(int kq, char *summary, size_t sumlen)
{
	unsigned i;
	unsigned reload_nremoved, reload_nchanged, reload_nnew;

	reload_nremoved = reload_nchanged = reload_nnew = 0;

	syslog(LOG_INFO, "reload: rescanning bundle directories");

	if (summary != NULL && sumlen > 0)
		summary[0] = '\0';

	if (sd.services == NULL) {
		syslog(LOG_WARNING, "reload: supervisor not initialized");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: supervisor not initialized\n");
		return (-1);
	}

	/*
	 * Rescan the bundle registry.  Teardown the old registry only
	 * after confirming the new one initializes successfully, so
	 * that a rescan failure does not break on-demand lookups that
	 * depend on the existing registry.
	 */
	bundle_registry_teardown();
	if (bundle_registry_init() == -1) {
		syslog(LOG_ERR, "reload: bundle registry rescan failed; "
		    "running services continue, on-demand lookups "
		    "unavailable until next successful reload");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: bundle rescan failed, "
			    "running services unaffected\n");
		return (0);
	}

	/* Invalidate bundle indices — the old registry is gone. */
	for (i = 0; i < sd.nservices; i++) {
		sd.services[i].bundle_idx = (unsigned)-1;
		sd.services[i].bundle_svc_idx = (unsigned)-1;
	}

	/*
	 * Phase 1: Stop services whose labels no longer exist in any bundle.
	 */
	{
		unsigned si, nstopped;

		nstopped = 0;
		for (si = 0; si < sd.nservices; si++) {
			struct svc_runtime *svc = &sd.services[si];
			struct svc_manifest desired;

			/* Check if this service's label still exists. */
			if (desired_service_manifest(svc->manifest.label,
			    &desired))
				continue;  /* still provided by a bundle */

			/* Service removed — stop it or remove its stopped slot. */
			if (svc->state == SVC_STATE_RUNNING ||
			    svc->state == SVC_STATE_STARTING) {
				syslog(LOG_INFO,
				    "reload: stopping removed service '%s'",
				    svc->manifest.label);
				svc_graceful_stop(svc, kq);
				svc->remove_pending = true;
				SERVICED_PROBE_SVC_REMOVED(svc->manifest.label);
				nstopped++;
				reload_nremoved++;
			} else if (svc->state == SVC_STATE_STOPPING) {
				svc->remove_pending = true;
				reload_nremoved++;
			} else {
				char removed_label[SERVICED_LABEL_MAX];

				strlcpy(removed_label, svc->manifest.label,
				    sizeof(removed_label));
				syslog(LOG_INFO,
				    "reload: removing stopped service '%s'",
				    removed_label);
				svc_remove(si);
				si--;
				SERVICED_PROBE_SVC_REMOVED(removed_label);
				reload_nremoved++;
			}
		}
		if (nstopped > 0)
			syslog(LOG_INFO, "reload: %u services marked for removal",
			    nstopped);
		/* Re-register kevents after svc_remove shifted the array. */
		if (reload_nremoved > 0)
			svc_reregister_kevents(kq);
	}

	/*
	 * Phase 2: Restart services whose bundle manifest changed.
	 */
	{
		unsigned si, nchanged;

		nchanged = 0;
		for (si = 0; si < sd.nservices; si++) {
			struct svc_runtime *svc = &sd.services[si];
			struct svc_manifest desired;

			if (svc->remove_pending)
				continue;
			if (!desired_service_manifest(svc->manifest.label,
			    &desired))
				continue;
			if (manifest_equal(&svc->manifest, &desired))
				continue;

			nchanged++;
			if (svc->state == SVC_STATE_RUNNING ||
			    svc->state == SVC_STATE_STARTING) {
				syslog(LOG_INFO,
				    "reload: restarting changed service '%s'",
				    svc->manifest.label);
				svc->pending_manifest = desired;
				svc->reload_pending = true;
				svc_graceful_stop(svc, kq);
			} else if (svc->state == SVC_STATE_STOPPING) {
				svc->pending_manifest = desired;
				svc->reload_pending = true;
			} else {
				syslog(LOG_INFO,
				    "reload: updating stopped service '%s'",
				    svc->manifest.label);
				svc->manifest = desired;
				svc->restart_count = 0;
			}
		}
		reload_nchanged = nchanged;
		if (nchanged > 0)
			syslog(LOG_INFO, "reload: %u services changed",
			    nchanged);
	}

	/*
	 * Phase 3: Collect new non-on-demand services, dependency-sort
	 * them, then launch in order.  This ensures correct startup
	 * ordering and detects cycles among newly added services.
	 */
	{
		unsigned bi, si, nnew_collected, nnew_launched;
		unsigned first_new;
		size_t off;

		nnew_collected = nnew_launched = 0;
		off = 0;
		first_new = sd.nservices;

		/* 3a: Collect new bundle services into the array. */
		for (bi = 0; bi < bundle_registry_count(); bi++) {
			struct capbundle *ab = bundle_registry_get(bi);
			struct capbundle_service *asvc;

			if (ab == NULL)
				continue;
			for (si = 0; si < capbundle_nservices(ab); si++) {
				struct svc_runtime *svc;

				asvc = capbundle_service(ab, si);
				if (asvc == NULL ||
				    capbundle_svc_on_demand(asvc))
					continue;
				if (svc_by_label(capbundle_svc_label(asvc))
				    != NULL)
					continue;
				if (sd.nservices >= SERVICED_MAX_SERVICES)
					break;

				svc = &sd.services[sd.nservices];
				memset(svc, 0, sizeof(*svc));
				svc->pd_fd = -1;
				svc->channel_fd = -1;
				svc->coalition_fd = -1;
				svc->jail_fd = -1;
				svc->state = SVC_STATE_STOPPED;
				svc->bundle_idx = bi;
				svc->bundle_svc_idx = si;
				strlcpy(svc->launched_by, "reload",
				    sizeof(svc->launched_by));

				if (capbundle_svc_fill_manifest(asvc,
				    &svc->manifest) == -1) {
					syslog(LOG_WARNING,
					    "reload: skipping invalid "
					    "bundle service '%s'",
					    capbundle_svc_label(asvc));
					continue;
				}
				sd.nservices++;
				nnew_collected++;
			}
		}

		/* 3b: Sort new services by dependency order. */
		if (nnew_collected > 1) {
			if (depgraph_sort(&sd.services[first_new],
			    nnew_collected) == -1) {
				syslog(LOG_ERR,
				    "reload: dependency sort failed "
				    "for new services, removing them");
				sd.nservices = first_new;
				nnew_collected = 0;
			}
		}

		/* 3c: Launch in sorted order. */
		for (i = first_new; i < first_new + nnew_collected; i++) {
			struct svc_runtime *svc = &sd.services[i];

			if (svc_exec(svc, kq) == 0) {
				syslog(LOG_INFO,
				    "reload: launched '%s'",
				    svc->manifest.label);
				SERVICED_PROBE_SVC_LOAD(
				    svc->manifest.label);
				nnew_launched++;
			} else {
				syslog(LOG_ERR,
				    "reload: failed to start '%s': %m",
				    svc->manifest.label);
				SERVICED_PROBE_SVC_EXEC_FAIL(
				    svc->manifest.label, errno);
			}
		}

		reload_nnew = nnew_launched;
		if (summary != NULL && sumlen > 0) {
			BUF_APPEND(summary, sumlen, &off,
			    "reload: %u bundles, %u new, "
			    "%u changed, %u removed\n",
			    bundle_registry_count(), nnew_launched,
			    reload_nchanged, reload_nremoved);
		}
	}

	syslog(LOG_INFO, "reload: %u new, %u changed, %u removed",
	    reload_nnew, reload_nchanged, reload_nremoved);
	return (0);
}
