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

#include <libappbundle.h>

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
	sd.services[sd.nservices].pair_fd = -1;
	sd.services[sd.nservices].coalition_fd = -1;
	sd.services[sd.nservices].jail_fd = -1;
}

static bool
manifest_equal(const struct svc_manifest *a, const struct svc_manifest *b)
{

	return (memcmp(a, b, sizeof(*a)) == 0);
}

static bool
bundle_service_manifest(const char *label, struct svc_manifest *m)
{
	unsigned bi, si;
	struct appbundle *ab;
	struct appbundle_service *asvc;

	if (bundle_registry_lookup(label, &bi, &si) == -1)
		return (false);
	ab = bundle_registry_get(bi);
	if (ab == NULL)
		return (false);
	asvc = appbundle_service(ab, si);
	if (asvc == NULL)
		return (false);
	return (appbundle_svc_fill_manifest(asvc, m) == 0);
}

static bool
legacy_service_manifest(const char *label, struct svc_manifest *m)
{
	const char *manifest_dir;
	DIR *d;
	struct dirent *de;
	bool found;

	manifest_dir = getenv("SERVICED_MANIFEST_DIR");
	if (manifest_dir == NULL || manifest_dir[0] == '\0')
		return (false);

	d = opendir(manifest_dir);
	if (d == NULL)
		return (false);

	found = false;
	while ((de = readdir(d)) != NULL) {
		struct svc_manifest lm;
		char path[PATH_MAX];
		size_t len;

		len = strlen(de->d_name);
		if (len < 5 || strcmp(de->d_name + len - 4, ".ucl") != 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", manifest_dir,
		    de->d_name);
		if (manifest_load_file(path, &lm) == -1)
			continue;
		if (strcmp(lm.label, label) == 0) {
			*m = lm;
			found = true;
			break;
		}
	}

	closedir(d);
	return (found);
}

static bool
desired_service_manifest(const char *label, struct svc_manifest *m)
{

	return (bundle_service_manifest(label, m) ||
	    legacy_service_manifest(label, m));
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

/*
 * Reload: re-scan bundle directories and diff against running services.
 * Add new services, stop removed ones.
 */
int
supervisor_reload(int kq, char *summary, size_t sumlen)
{
	unsigned i;

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
	 * Rescan the bundle registry and launch any new non-on-demand
	 * services that aren't already running.
	 */
	bundle_registry_teardown();

	/*
	 * Invalidate bundle indices in all running services.
	 * The old bundle_idx/bundle_svc_idx pointed into the
	 * now-freed registry.
	 */
	for (i = 0; i < sd.nservices; i++) {
		sd.services[i].bundle_idx = (unsigned)-1;
		sd.services[i].bundle_svc_idx = (unsigned)-1;
	}

	if (bundle_registry_init() == -1) {
		syslog(LOG_ERR, "reload: bundle registry rescan failed; "
		    "running services continue, no new launches until "
		    "next successful reload");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: bundle rescan failed, "
			    "running services unaffected\n");
		return (0);
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
			} else if (svc->state == SVC_STATE_STOPPING) {
				svc->remove_pending = true;
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
			}
		}
		if (nstopped > 0)
			syslog(LOG_INFO, "reload: %u services marked for removal",
			    nstopped);
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
		if (nchanged > 0)
			syslog(LOG_INFO, "reload: %u services changed",
			    nchanged);
	}

	/*
	 * Phase 3: Launch new non-on-demand services not already running.
	 */
	{
		unsigned bi, si, nnew_launched;
		size_t off;

		nnew_launched = 0;
		off = 0;
		for (bi = 0; bi < bundle_registry_count(); bi++) {
			struct appbundle *ab = bundle_registry_get(bi);
			if (ab == NULL)
				continue;
			for (si = 0; si < appbundle_nservices(ab); si++) {
				struct appbundle_service *asvc =
				    appbundle_service(ab, si);
				if (asvc == NULL || appbundle_svc_on_demand(asvc))
					continue;
				/* Skip if already loaded. */
				if (svc_by_label(appbundle_svc_label(asvc))
				    != NULL)
					continue;
				if (sd.nservices >= SERVICED_MAX_SERVICES)
					break;
				/* Add and launch. */
				{
					struct svc_runtime *svc;

					svc = &sd.services[sd.nservices];
					memset(svc, 0, sizeof(*svc));
					svc->pd_fd = -1;
					svc->pair_fd = -1;
					svc->coalition_fd = -1;
					svc->jail_fd = -1;
					svc->state = SVC_STATE_STOPPED;
					svc->bundle_idx = bi;
					svc->bundle_svc_idx = si;
					strlcpy(svc->launched_by, "reload",
					    sizeof(svc->launched_by));

					if (appbundle_svc_fill_manifest(asvc,
					    &svc->manifest) == -1) {
						syslog(LOG_WARNING,
						    "reload: skipping "
						    "invalid bundle "
						    "service '%s'",
						    appbundle_svc_label(
						    asvc));
						memset(svc, 0,
						    sizeof(*svc));
						svc->pd_fd = -1;
						svc->pair_fd = -1;
						svc->coalition_fd = -1;
						svc->jail_fd = -1;
						continue;
					}
					sd.nservices++;

					if (svc_exec(svc, kq) == 0) {
						syslog(LOG_INFO,
						    "reload: launched '%s'",
						    svc->manifest.label);
						SERVICED_PROBE_SVC_LOAD(
						    svc->manifest.label);
						nnew_launched++;
					} else {
						syslog(LOG_ERR,
						    "reload: failed to start"
						    " '%s': %m",
						    svc->manifest.label);
						SERVICED_PROBE_SVC_EXEC_FAIL(
						    svc->manifest.label, errno);
						/* Rollback: remove the slot
						 * so future reloads can
						 * retry this service. */
						memset(svc, 0, sizeof(*svc));
						sd.nservices--;
					}
				}
			}
		}

		{
			const char *manifest_dir;
			DIR *d;
			struct dirent *de;

			manifest_dir = getenv("SERVICED_MANIFEST_DIR");
			if (manifest_dir != NULL && manifest_dir[0] != '\0' &&
			    (d = opendir(manifest_dir)) != NULL) {
				while ((de = readdir(d)) != NULL) {
					struct svc_runtime *svc;
					struct svc_manifest m;
					char path[PATH_MAX];
					size_t len;

					len = strlen(de->d_name);
					if (len < 5 ||
					    strcmp(de->d_name + len - 4,
					    ".ucl") != 0)
						continue;
					snprintf(path, sizeof(path), "%s/%s",
					    manifest_dir, de->d_name);
					if (manifest_load_file(path, &m) == -1)
						continue;
					if (svc_by_label(m.label) != NULL)
						continue;
					if (sd.nservices >= SERVICED_MAX_SERVICES)
						break;

					svc = &sd.services[sd.nservices];
					memset(svc, 0, sizeof(*svc));
					svc->manifest = m;
					svc->pd_fd = -1;
					svc->pair_fd = -1;
					svc->coalition_fd = -1;
					svc->jail_fd = -1;
					svc->state = SVC_STATE_STOPPED;
					svc->bundle_idx = (unsigned)-1;
					svc->bundle_svc_idx = (unsigned)-1;
					strlcpy(svc->launched_by, "reload",
					    sizeof(svc->launched_by));
					sd.nservices++;

					if (svc_exec(svc, kq) == 0) {
						syslog(LOG_INFO,
						    "reload: launched '%s'",
						    svc->manifest.label);
						SERVICED_PROBE_SVC_LOAD(
						    svc->manifest.label);
						nnew_launched++;
					} else {
						syslog(LOG_ERR,
						    "reload: failed to start "
						    "'%s': %m",
						    svc->manifest.label);
						SERVICED_PROBE_SVC_EXEC_FAIL(
						    svc->manifest.label, errno);
						memset(svc, 0, sizeof(*svc));
						svc->pd_fd = -1;
						svc->pair_fd = -1;
						svc->coalition_fd = -1;
						svc->jail_fd = -1;
						sd.nservices--;
					}
				}
				closedir(d);
			}
		}
		if (summary != NULL && sumlen > 0) {
			BUF_APPEND(summary, sumlen, &off,
			    "reload: %u bundles", bundle_registry_count());
			if (nnew_launched > 0)
				BUF_APPEND(summary, sumlen, &off,
				    ", %u new launched", nnew_launched);
			BUF_APPEND(summary, sumlen, &off, "\n");
		}
	}
	return (0);
}
