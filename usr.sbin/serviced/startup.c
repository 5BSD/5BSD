/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Tier-based parallel service startup for serviced.
 *
 * After topological sort, services are grouped into tiers (layers
 * of the dependency DAG).  All services in a tier launch in parallel.
 * We wait for all services in a tier to report ready before launching
 * the next tier.  This minimizes startup time while respecting
 * inter-service dependencies.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/param.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <libcapbundle.h>

#include "serviced.h"
#include "serviced_probes.h"

#define	TIER_READY_TIMEOUT_SEC	10

/*
 * Log a loaded manifest's key attributes for operational visibility.
 */
static void
log_loaded_manifest(const struct svc_manifest *m)
{
	unsigned j;

	syslog(LOG_INFO, "startup: loaded %s restart=%s",
	    m->label, restart_policy_name(m->restart));

	for (j = 0; j < m->nprovides; j++)
		syslog(LOG_INFO, "startup: %s provides: %s",
		    m->label, m->provides[j]);
	for (j = 0; j < m->nrequires; j++)
		syslog(LOG_INFO, "startup: %s requires: %s",
		    m->label, m->requires[j]);

	if (m->ncap_paths + m->ncap_files + m->ncap_net +
	    m->cap_system > 0)
		syslog(LOG_INFO, "startup: %s capabilities: "
		    "paths=%u files=%u network=%u system=0x%x",
		    m->label, m->ncap_paths, m->ncap_files,
		    m->ncap_net, m->cap_system);

	if (m->has_jail)
		syslog(LOG_INFO, "startup: %s jail: %s path=%s",
		    m->label, m->jail_name, m->jail_path);
}

/*
 * Assign tiers based on dependency depth.
 * Tier 0 = no dependencies.  Tier N = max(tier of each requires) + 1.
 *
 * svcs must already be topologically sorted.
 * Returns the maximum tier number.
 */
static unsigned
assign_tiers(struct svc_runtime *svcs, unsigned n, unsigned *tiers)
{
	unsigned i, j, k, max_tier;

	max_tier = 0;
	for (i = 0; i < n; i++) {
		tiers[i] = 0;
		for (j = 0; j < svcs[i].manifest.nrequires; j++) {
			/* Find the tier of the required service. */
			for (k = 0; k < i; k++) {
				unsigned p;
				for (p = 0; p < svcs[k].manifest.nprovides; p++) {
					if (strcmp(svcs[i].manifest.requires[j],
					    svcs[k].manifest.provides[p]) == 0) {
						if (tiers[k] + 1 > tiers[i])
							tiers[i] = tiers[k] + 1;
					}
				}
			}
		}
		if (tiers[i] > max_tier)
			max_tier = tiers[i];
	}
	return (max_tier);
}

/*
 * Wait for all services in a tier to report SVC_OP_READY.
 * Returns 0 if all ready, -1 if timeout (some services may be stuck).
 */
static int
wait_tier_ready(struct svc_runtime *svcs, unsigned n, unsigned tier,
    unsigned *tiers, int kq)
{
	struct kevent events[16];
	struct timespec deadline, now;
	unsigned ready_count, needed;
	unsigned i;
	int nev;

	/* Count how many services we need to wait for. */
	needed = 0;
	for (i = 0; i < n; i++) {
		if (tiers[i] == tier &&
		    svcs[i].state == SVC_STATE_STARTING)
			needed++;
	}

	if (needed == 0)
		return (0);

	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += TIER_READY_TIMEOUT_SEC;

	ready_count = 0;
	while (ready_count < needed) {
		struct timespec remain;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		    now.tv_nsec >= deadline.tv_nsec)) {
			syslog(LOG_WARNING,
			    "startup: tier %u timeout (%u/%u ready)",
			    tier, ready_count, needed);
			return (-1);
		}

		remain.tv_sec = deadline.tv_sec - now.tv_sec;
		remain.tv_nsec = deadline.tv_nsec - now.tv_nsec;
		if (remain.tv_nsec < 0) {
			remain.tv_sec--;
			remain.tv_nsec += 1000000000L;
		}

		nev = kevent(kq, NULL, 0, events, 16, &remain);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}

		for (i = 0; (int)i < nev; i++) {
			if (events[i].filter == EVFILT_PROCDESC)
				supervisor_handle_procdesc(&events[i]);
			else if (events[i].filter == EVFILT_READ &&
			    events[i].udata != NULL)
				supervisor_handle_pair(&events[i]);
			else if (events[i].filter == EVFILT_TIMER)
				supervisor_handle_timer(&events[i]);
			else if (events[i].filter == EVFILT_SIGNAL) {
				int sig = (int)events[i].ident;

				if (sig == SIGTERM || sig == SIGINT) {
					syslog(LOG_INFO,
					    "startup: signal %d during "
					    "tier wait, aborting", sig);
					sd.running = false;
					return (-1);
				}
			}
		}

		/* Recount ready + crashed services. */
		ready_count = 0;
		for (i = 0; i < n; i++) {
			if (tiers[i] != tier)
				continue;
			if (svcs[i].state == SVC_STATE_RUNNING ||
			    svcs[i].state == SVC_STATE_STOPPED)
				ready_count++;
		}
	}

	return (0);
}

/*
 * Launch all system services using tier-based parallelism.
 *
 * 1. Scan bundle registry for non-on-demand services
 * 2. Fill svc_runtime array with manifests from bundles
 * 3. Topological sort
 * 4. Assign tiers
 * 5. For each tier: launch all, wait for ready
 */
int
startup_launch_system(int kq)
{
	struct svc_manifest *manifests;
	unsigned nmanifests, i, bi, si;
	unsigned *tiers;
	unsigned max_tier, tier;
	struct capbundle *b;
	struct capbundle_service *asvc;
	struct timespec start_ts;

	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	/* Collect all non-on-demand service manifests from bundles. */
	manifests = calloc(SERVICED_MAX_SERVICES, sizeof(*manifests));
	if (manifests == NULL) {
		syslog(LOG_ERR, "startup: calloc: %m");
		return (-1);
	}

	nmanifests = 0;
	for (bi = 0; bi < bundle_registry_count(); bi++) {
		b = bundle_registry_get(bi);
		if (b == NULL)
			continue;

		for (si = 0; si < capbundle_nservices(b); si++) {
			asvc = capbundle_service(b, si);
			if (asvc == NULL)
				continue;
			if (capbundle_svc_on_demand(asvc))
				continue;
			if (nmanifests >= SERVICED_MAX_SERVICES) {
				syslog(LOG_WARNING,
				    "startup: service limit reached");
				break;
			}

			/* Fill svc_manifest from bundle service. */
			if (capbundle_svc_fill_manifest(asvc,
			    &manifests[nmanifests]) == -1) {
				syslog(LOG_WARNING,
				    "startup: skipping invalid bundle service "
				    "'%s'", capbundle_svc_label(asvc));
				continue;
			}
			log_loaded_manifest(&manifests[nmanifests]);
			nmanifests++;
		}
	}

	/* Collect legacy absolute-path manifests, if oracled provided a dir. */
	{
		const char *manifest_dir;
		DIR *d;
		struct dirent *de;

		manifest_dir = getenv("SERVICED_MANIFEST_DIR");
		if (manifest_dir != NULL && manifest_dir[0] != '\0') {
			d = opendir(manifest_dir);
			if (d == NULL) {
				syslog(LOG_INFO,
				    "startup: manifest dir %s not available: %m",
				    manifest_dir);
			} else {
				while ((de = readdir(d)) != NULL) {
					char path[PATH_MAX];
					size_t len;

					len = strlen(de->d_name);
					if (len < 5 ||
					    strcmp(de->d_name + len - 4,
					    ".ucl") != 0)
						continue;
					if (nmanifests >= SERVICED_MAX_SERVICES) {
						syslog(LOG_WARNING,
						    "startup: service limit "
						    "reached");
						break;
					}
					snprintf(path, sizeof(path), "%s/%s",
					    manifest_dir, de->d_name);
					if (manifest_load_file(path,
					    &manifests[nmanifests]) == 0) {
						log_loaded_manifest(
						    &manifests[nmanifests]);
						nmanifests++;
					}
				}
				closedir(d);
			}
		}
	}

	/* Allocate runtime state — always, even with no boot services,
	 * because on-demand launches and reload append to this array. */
	sd.services = calloc(SERVICED_MAX_SERVICES, sizeof(*sd.services));
	if (sd.services == NULL) {
		syslog(LOG_ERR, "startup: calloc services: %m");
		free(manifests);
		return (-1);
	}

	syslog(LOG_INFO, "startup: %u services loaded", nmanifests);

	if (nmanifests == 0) {
		syslog(LOG_INFO, "startup: no boot services to launch");
		free(manifests);
		return (0);
	}

	/* Copy manifests into runtime slots. */
	for (i = 0; i < nmanifests; i++) {
		sd.services[i].manifest = manifests[i];
		sd.services[i].pd_fd = -1;
		sd.services[i].pair_fd = -1;
		sd.services[i].coalition_fd = -1;
		sd.services[i].jail_fd = -1;
		sd.services[i].state = SVC_STATE_STOPPED;
		strlcpy(sd.services[i].launched_by, "system",
		    sizeof(sd.services[i].launched_by));
		clock_gettime(CLOCK_MONOTONIC, &sd.services[i].launch_time);
	}
	sd.nservices = nmanifests;
	free(manifests);

	/* Topological sort. */
	if (depgraph_sort(sd.services, sd.nservices) == -1) {
		syslog(LOG_ERR, "startup: dependency sort failed");
		return (-1);
	}

	/* Assign tiers. */
	tiers = calloc(sd.nservices, sizeof(*tiers));
	if (tiers == NULL) {
		syslog(LOG_ERR, "startup: calloc tiers: %m");
		return (-1);
	}
	max_tier = assign_tiers(sd.services, sd.nservices, tiers);

	syslog(LOG_INFO, "startup: %u services in %u tiers",
	    sd.nservices, max_tier + 1);
	SERVICED_PROBE_STARTUP_BEGIN(sd.nservices, max_tier + 1);

	/* Launch tier by tier. */
	for (tier = 0; tier <= max_tier; tier++) {
		unsigned launched = 0;

		for (i = 0; i < sd.nservices; i++) {
			if (tiers[i] != tier)
				continue;
			syslog(LOG_INFO, "startup: service: %s",
			    sd.services[i].manifest.label);
			if (svc_exec(&sd.services[i], kq) == 0)
				launched++;
			else
				syslog(LOG_ERR, "startup: failed to launch '%s'",
				    sd.services[i].manifest.label);
		}

		syslog(LOG_INFO, "startup: tier %u — launched %u services",
		    tier, launched);
		SERVICED_PROBE_STARTUP_TIER(tier, launched);

		/* Wait for this tier to become ready before next tier. */
		if (tier < max_tier && launched > 0) {
			if (wait_tier_ready(sd.services, sd.nservices,
			    tier, tiers, kq) == -1) {
				syslog(LOG_ERR,
				    "startup: tier %u did not become ready",
				    tier);
				free(tiers);
				return (-1);
			}
		}
	}

	free(tiers);

	{
		struct timespec end_ts;
		uint64_t dur_ms;

		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		dur_ms = (uint64_t)(end_ts.tv_sec - start_ts.tv_sec) * 1000 +
		    (uint64_t)(end_ts.tv_nsec - start_ts.tv_nsec) / 1000000;
		syslog(LOG_INFO, "startup: complete in %llu ms",
		    (unsigned long long)dur_ms);
		SERVICED_PROBE_STARTUP_DONE(dur_ms);
	}

	return (0);
}
