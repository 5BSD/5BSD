/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Hot-reload logic for switchboard.
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

#include "switchboard.h"
#include "authority.h"
#include "management.h"
#include "manifest_compare.h"
#include "switchboard_audit.h"
#include "switchboard_probes.h"
#include "switchboard_svc_proto.h"

struct svc_runtime *
svc_by_label_scoped(const char *label, uid_t owner_uid)
{
	unsigned i;

	for (i = 0; i < sd.nservices; i++) {
		if (sd.services[i]->owner_uid == owner_uid &&
		    strcmp(sd.services[i]->manifest.label, label) == 0)
			return (sd.services[i]);
	}
	return (NULL);
}

struct svc_runtime *
svc_by_label(const char *label)
{
	return (svc_by_label_scoped(label, (uid_t)-1));
}

/*
 * Remove a unit from the index and free it.  A unit whose previous coalition
 * is still being cleaned up is only marked; cleanup completion removes it.
 * Units are separate allocations, so removal never moves another unit and
 * nothing registered on another unit's behalf needs to be told.  Everything
 * still registered with this unit's address is dropped here, before the
 * free.
 */
void
svc_remove(struct svc_runtime *svc)
{
	unsigned idx;

	for (idx = 0; idx < sd.nservices && sd.services[idx] != svc; idx++)
		;
	if (idx == sd.nservices)
		return;
	if (svc->cleanup.pending) {
		svc->remove_pending = true;
		return;
	}

	/* Abandon any launch in progress, releasing its descriptors. */
	if (svc->launch != NULL)
		svc_launch_cancel(svc, switchboard_kq);

	/*
	 * Activation sources outlive the unit's own start/stop cycles, so
	 * removal is the only point they are dropped.
	 */
	activation_source_teardown(svc, switchboard_kq);
	supervisor_disarm_timers(svc, switchboard_kq);
	naming_remove_owner(svc);
	svc_channel_close(svc);
	/* A stopped unit holds no process; close what a caller left behind. */
	if (svc->pd_fd >= 0)
		(void)close(svc->pd_fd);
	if (svc->coalition_fd >= 0)
		(void)close(svc->coalition_fd);
	svc_responsibility_clear(svc);

	memmove(&sd.services[idx], &sd.services[idx + 1],
	    (sd.nservices - idx - 1) * sizeof(sd.services[0]));
	sd.nservices--;
	sd.services[sd.nservices] = NULL;
	free(svc);
}

/* Compare and queue the policy that launch actually enforces. */
static bool
bundle_effective_manifest(struct capbundle_service *unit, unsigned bi,
    struct svc_manifest *manifest)
{
	struct svc_runtime *candidate;
	bool valid;

	candidate = calloc(1, sizeof(*candidate));
	if (candidate == NULL)
		return (false);
	valid = capbundle_svc_fill_manifest(unit, &candidate->manifest) == 0;
	if (valid) {
		svc_slot_apply_bundle_policy(candidate, bi);
		valid = svc_user_manifest_credentials(candidate) == 0;
		if (valid)
			*manifest = candidate->manifest;
	}
	free(candidate);
	return (valid);
}

static bool
bundle_service_manifest(const char *label, uid_t owner_uid, struct svc_manifest *m)
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
	if (bundle_registry_lookup_scoped(label, owner_uid, &bi, &si) == 0) {
		ab = bundle_registry_get(bi);
		if (ab != NULL) {
			asvc = capbundle_service(ab, si);
			if (asvc != NULL &&
			    strcmp(capbundle_svc_label(asvc), label) == 0)
				return (bundle_effective_manifest(asvc, bi, m));
		}
	}

	/* Linear scan: label may differ from provides names. */
	for (bi = 0; bi < bundle_registry_count(); bi++) {
		ab = bundle_registry_get(bi);
		if (bundle_registry_owner_uid(bi) != owner_uid)
			continue;
		if (ab == NULL)
			continue;
		for (si = 0; si < capbundle_nservices(ab); si++) {
			asvc = capbundle_service(ab, si);
			if (asvc == NULL)
				continue;
			if (strcmp(capbundle_svc_label(asvc), label) == 0)
				return (bundle_effective_manifest(asvc, bi, m));
		}
	}
	return (false);
}

static bool
desired_service_manifest(const char *label, uid_t owner_uid, struct svc_manifest *m)
{
	return (bundle_service_manifest(label, owner_uid, m));
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

	/* A shutdown starts nothing, so it loads nothing either. */
	if (sd.shutting_down) {
		syslog(LOG_NOTICE, "reload: refused, shutting down");
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen, "error: shutting down\n");
		return (-1);
	}
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
		 * The previous registry is still authoritative.
		 */
		return (-1);
	}

	/* Invalidate bundle indices — the old registry is gone. */
	for (i = 0; i < sd.nservices; i++) {
		sd.services[i]->bundle_idx = (unsigned)-1;
		sd.services[i]->bundle_svc_idx = (unsigned)-1;
	}

	/* Rebind retained native slots by canonical label. A restart resolves its
	 * default discovery domain from this origin; leaving the index invalid
	 * silently turns a system provider into a user-domain client after reload. */
	for (unsigned bi = 0; bi < bundle_registry_count(); bi++) {
		struct capbundle *b = bundle_registry_get(bi);
		if (b == NULL)
			continue;
		for (unsigned si = 0; si < capbundle_nservices(b); si++) {
			struct capbundle_service *asvc = capbundle_service(b, si);
			struct svc_runtime *svc;
			if (asvc == NULL || (svc = svc_by_label_scoped(capbundle_svc_label(asvc),
			    bundle_registry_owner_uid(bi))) == NULL ||
			    svc->kind == SVC_KIND_RC)
				continue;
			svc->bundle_idx = bi;
			svc->bundle_svc_idx = si;
		}
	}

	/*
	 * Phase 1: Stop services whose labels no longer exist in any bundle.
	 */
	{
		unsigned si, nstopped;

		nstopped = 0;
		for (si = 0; si < sd.nservices; si++) {
			struct svc_runtime *svc = sd.services[si];

			/* RC units belong to rc.d adoption, not the bundle registry.
			 * A bundle rescan must not stop an adopted daemon simply
			 * because it has no capability bundle. */
			if (svc->kind == SVC_KIND_RC)
				continue;

			/* Check if this service's label still exists. */
			if (desired_service_manifest(svc->manifest.label, svc->owner_uid,
			    &desired)) {
				/*
				 * Still provided.  If an earlier rescan had marked
				 * it for removal and it is still draining, revive
				 * it: the exit path re-execs a reload_pending
				 * service with its pending manifest instead of
				 * removing its slot -- otherwise a unit whose
				 * bundle was momentarily unreadable would stay
				 * gone until an unrelated folder change.
				 */
				if (svc->remove_pending &&
				    svc->state == SVC_STATE_STOPPING) {
					syslog(LOG_INFO, "reload: service '%s' "
					    "is provided again; relaunching it "
					    "after its stop completes",
					    svc->manifest.label);
					svc->remove_pending = false;
					svc->pending_manifest = desired;
					svc->reload_pending = true;
				}
				continue;
			}

			/*
			 * Absolute management-class rule (§5): a core unit may
			 * not be unloaded at runtime, even when its bundle has
			 * gone away (operator disable/uninstall).  Retain it —
			 * only the shutdown lifecycle tears a core unit down.
			 */
			if (svc_management_check_op(svc, "unloaded", (uid_t)-1, /*is_operator=*/true) != 0)
				continue;

			/* Service removed — stop it or remove its stopped slot. */
			if (svc->state == SVC_STATE_RUNNING ||
			    svc->state == SVC_STATE_STARTING) {
				syslog(LOG_INFO,
				    "reload: stopping removed service '%s'",
				    svc->manifest.label);
				svc_graceful_stop(svc, kq);
				svc->remove_pending = true;
				SWITCHBOARD_PROBE_SVC_REMOVED(svc->manifest.label);
				nstopped++;
				reload_nremoved++;
			} else if (svc->state == SVC_STATE_STOPPING) {
				svc->remove_pending = true;
				reload_nremoved++;
			} else {
				char removed_label[SWITCHBOARD_LABEL_MAX];

				strlcpy(removed_label, svc->manifest.label,
				    sizeof(removed_label));
				syslog(LOG_INFO,
				    "reload: removing stopped service '%s'",
				    removed_label);
				svc_remove(svc);
				si--;
				SWITCHBOARD_PROBE_SVC_REMOVED(removed_label);
				reload_nremoved++;
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
			struct svc_runtime *svc = sd.services[si];

			if (svc->kind == SVC_KIND_RC || svc->remove_pending)
				continue;
			if (!desired_service_manifest(svc->manifest.label, svc->owner_uid,
			    &desired))
				continue;
			if (switchboard_manifest_equal(&svc->manifest, &desired))
				continue;
			/*
			 * A core image and its launch policy belong to the
			 * trusted system generation.  Never replace either from
			 * a live registry rescan; a verified next boot performs
			 * core updates.
			 */
			if (svc_management_check_op(svc,
			    "changed at runtime", (uid_t)-1, true) != 0)
				continue;

			nchanged++;
			SWITCHBOARD_PROBE_SVC_CHANGED(svc->manifest.label);
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
				svc_slot_apply_bundle_policy(svc, svc->bundle_idx);
				svc->restart_count = 0;
				/*
				 * Re-arm activation with the new manifest.  A
				 * stopped on-demand unit keeps its activation
				 * sources (timer/path/queue/mount/socket) armed to
				 * trigger relaunch; tear the old ones down so the
				 * activation_register_all() at the end of reload
				 * re-arms them from the updated manifest (it is
				 * idempotent and would otherwise skip the
				 * still-armed old sources), or a changed interval /
				 * watch path / socket is silently ignored.
				 */
				activation_source_teardown(svc, kq);
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
				if (svc_by_label_scoped(capbundle_svc_label(asvc),
			    bundle_registry_owner_uid(bi))
				    != NULL)
					continue;
				svc = svc_unit_alloc();
				if (svc == NULL) {
					syslog(LOG_WARNING, "reload: cannot "
					    "add '%s': %m",
					    capbundle_svc_label(asvc));
					continue;
				}
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
					free(svc);
					continue;
				}
				svc_slot_apply_bundle_policy(svc, bi);
				svc_unit_publish(svc);
				nnew_collected++;
			}
		}

		/* 3b: Launch new services in parallel (no startup ordering). */
		for (i = first_new; i < first_new + nnew_collected; i++) {
			struct svc_runtime *svc = sd.services[i];

			if (svc_launch_or_await(svc, kq) == 0) {
				syslog(LOG_INFO,
				    "reload: launched '%s'",
				    svc->manifest.label);
				SWITCHBOARD_PROBE_SVC_LOAD(
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
				SWITCHBOARD_PROBE_SVC_EXEC_FAIL(
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

	/*
	 * Re-publish the running-bundle markers: a reload is where an uninstall
	 * becomes visible (the bundle left System/Apps and Phase 1 unloaded its
	 * unit).  Refreshing the markers here drops the stopped bundle's marker,
	 * so once its container is also gone from the installed set the reconcile
	 * may reap it -- never before the unit was unloaded (unload-first).
	 */
	svc_reclaim_publish_live();

	syslog(LOG_INFO, "reload: %u new, %u changed, %u removed",
	    reload_nnew, reload_nchanged, reload_nremoved);
	SWITCHBOARD_PROBE_RELOAD(reload_nnew, reload_nchanged, reload_nremoved);
	SWITCHBOARD_PROBE_SVC_COUNT(sd.nservices);

	/*
	 * Record the configuration change in the audit trail; a reload alters
	 * which services run and with what privileges.
	 */
	switchboard_audit(AUE_SWITCHBOARD_RELOAD, getuid(), 0,
	    "reload: %u new, %u changed, %u removed",
	    reload_nnew, reload_nchanged, reload_nremoved);
	if (svc_authority_applications_sync() == -1) {
		if (summary != NULL && sumlen > 0)
			snprintf(summary, sumlen,
			    "error: service reload applied; application catalogue update failed\n");
		return (-1);
	}
	return (0);
}
