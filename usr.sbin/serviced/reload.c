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
#include <unistd.h>

#include <libcapbundle.h>

#include "serviced.h"
#include "management.h"
#include "manifest_compare.h"
#include "serviced_audit.h"
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

	/* Abandon any async launch on the slot before it is overwritten, so
	 * its descriptors are released and its session event is unregistered. */
	if (sd.services[idx].launch != NULL)
		svc_launch_cancel(&sd.services[idx], serviced_kq);

	/*
	 * Tear down this unit's activation sources (Phase 5) before the slot is
	 * shifted away: the periodic timer and vnode watch outlive the unit's
	 * own start/stop cycles, so removal is the only point they are dropped.
	 */
	activation_source_teardown(&sd.services[idx], serviced_kq);

	for (i = idx; i < sd.nservices - 1; i++) {
		sd.services[i] = sd.services[i + 1];
		naming_rebind_owner(&sd.services[i + 1], &sd.services[i]);
	}

	sd.nservices--;

	/* Clear the vacated slot. */
	memset(&sd.services[sd.nservices], 0, sizeof(sd.services[0]));
	svc_runtime_init_fds(&sd.services[sd.nservices]);
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
 * Called after svc_remove() shifts array entries (Phase 1).
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
			    EV_ADD, NOTE_EXIT | NOTE_EXEC | NOTE_CAPMODE, 0, svc);
			if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
				syslog(LOG_WARNING,
				    "reload: re-register pd_fd for %s: %m",
				    svc->manifest.label);
		}
		if (svc->channel_fd >= 0) {
			if (svc_channel_rebind(svc) == -1)
				syslog(LOG_WARNING,
				    "reload: rebind channel for %s: %m",
				    svc->manifest.label);
			EV_SET(&kev, svc->channel_fd, EVFILT_READ,
			    EV_ADD, 0, 0, svc);
			if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
				syslog(LOG_WARNING,
				    "reload: re-register channel_fd for %s: %m",
				    svc->manifest.label);
			svc_channel_sync_events(svc, kq);
		}
		if (svc->coalition_fd >= 0) {
			EV_SET(&kev, svc->coalition_fd, EVFILT_READ,
			    EV_ADD, 0, 0, svc);
			if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
				syslog(LOG_WARNING,
				    "reload: re-register coalition_fd "
				    "for %s: %m", svc->manifest.label);
		}
		/*
		 * Re-schedule a pending restart timer with the post-compaction
		 * udata.  The old timer was NOT cancelled before the reload
		 * compaction, and its EVFILT_TIMER udata still points at this
		 * service's pre-move slot address — which now holds a different
		 * service — so it must be EV_DELETEd first (svc_cancel_restart),
		 * or when it fires supervisor_handle_timer reads restart/idle
		 * state off the wrong service.  Then arm a fresh one carrying the
		 * correct udata.
		 */
		if (svc->restart_pending) {
			svc_cancel_restart(svc, kq);
			schedule_restart(svc, kq);
		}
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
	/* The daemon is single-threaded; keep the 80-KiB scratch manifest off
	 * its deliberately small control-path stack. */
	static struct svc_manifest desired;
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
	 * Rescan the registry transactionally.  A malformed replacement leaves
	 * both running services and the previous on-demand registry intact.
	 */
	if (bundle_registry_init() == -1) {
		syslog(LOG_ERR, "reload: bundle registry rescan failed; "
		    "previous registry and running services retained");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: bundle rescan failed, "
			    "running services unaffected\n");
		/*
		 * Return -1 so the caller knows no replacement state was applied.
		 */
		return (-1);
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

			/* Check if this service's label still exists. */
			if (desired_service_manifest(svc->manifest.label,
			    &desired))
				continue;  /* still provided by a bundle */

			/*
			 * Absolute management-class rule (§5): a core unit may
			 * not be unloaded at runtime, even when its bundle has
			 * gone away (operator disable/uninstall).  Retain it —
			 * only the shutdown lifecycle tears a core unit down.
			 * This is orthogonal to reload-on-manifest-change
			 * (Phase 2), which still restarts core units in place.
			 */
			if (svc_management_check_op(svc, "unloaded") != 0)
				continue;

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

			if (svc->remove_pending)
				continue;
			if (!desired_service_manifest(svc->manifest.label,
			    &desired))
				continue;
			if (serviced_manifest_equal(&svc->manifest, &desired))
				continue;

			nchanged++;
			SERVICED_PROBE_SVC_CHANGED(svc->manifest.label);
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
				/*
				 * Only boot units are launched on reload.  Units
				 * activated on demand — by IPC lookup, timer, or
				 * path (Phase 5) — get their stopped slot and
				 * armed source from activation_register_all()
				 * below, not an eager launch here.
				 */
				if (asvc == NULL ||
				    !capbundle_svc_activates_at_boot(asvc))
					continue;
				if (svc_by_label(capbundle_svc_label(asvc))
				    != NULL)
					continue;
				if (sd.nservices >= SERVICED_MAX_SERVICES)
					break;

				svc = &sd.services[sd.nservices];
				memset(svc, 0, sizeof(*svc));
				svc_runtime_init_fds(svc);
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

		/* 3b: Launch new services in parallel (no startup ordering). */
		for (i = first_new; i < first_new + nnew_collected; i++) {
			struct svc_runtime *svc = &sd.services[i];

			if (svc_launch_or_await(svc, kq) == 0) {
				syslog(LOG_INFO,
				    "reload: launched '%s'",
				    svc->manifest.label);
				SERVICED_PROBE_SVC_LOAD(
				    svc->manifest.label);
				nnew_launched++;
			} else {
				/* Consumed only by the DTrace probe below. */
				int exec_errno __unused = errno;

				syslog(LOG_ERR,
				    "reload: failed to start '%s': %m",
				    svc->manifest.label);
				/* Report the errno from svc_exec, not the one
				 * the intervening syslog() may have set. */
				SERVICED_PROBE_SVC_EXEC_FAIL(
				    svc->manifest.label, exec_errno);
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

	/*
	 * Register timer/path activation sources (Phase 5) for any newly added
	 * demand-activated units, and arm newly declared sources on units that
	 * persisted.  Idempotent: sources already armed are left in place.
	 */
	(void)activation_register_all(kq);

	syslog(LOG_INFO, "reload: %u new, %u changed, %u removed",
	    reload_nnew, reload_nchanged, reload_nremoved);
	SERVICED_PROBE_RELOAD(reload_nnew, reload_nchanged, reload_nremoved);
	SERVICED_PROBE_SVC_COUNT(sd.nservices);

	/*
	 * Record the configuration change in the audit trail; a reload alters
	 * which services run and with what privileges.
	 */
	serviced_audit(AUE_SERVICED_RELOAD, getuid(), 0,
	    "reload: %u new, %u changed, %u removed",
	    reload_nnew, reload_nchanged, reload_nremoved);
	return (0);
}
