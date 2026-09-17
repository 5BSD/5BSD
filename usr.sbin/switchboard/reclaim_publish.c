/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Publish the running-bundle markers for the container-model reconcile.
 *
 * Cleanup of per-capability storage is a reconcile, never an event: a provider
 * compares the containers it holds (Data/<bundle>/) against the live set and
 * reaps the rest (docs/capability-container-model.md).  The live set is
 * installed OR running.  "Installed" needs no help from switchboard -- it is the
 * pkg-owned System/ and Apps/ directories, which the provider reads directly.
 * "Running" is switchboard's to express: this writes one marker per running
 * unit's bundle under /Capabilities/Run/live/, so a bundle whose unit has not
 * yet been unloaded (mid-uninstall) is never mistaken for an orphan.  Markers
 * live in their own subdirectory, apart from the sockets under Run/.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "switchboard.h"
#include "switchboard_probes.h"

#define	BUNDLE_MAX	64

/*
 * The markers must track every state change, not just boot and reload: a unit
 * restarted after a manifest change, relaunched on failure or on demand, or
 * exited, changes the running set asynchronously.  Those paths mark the set
 * dirty and the event loop republishes once per iteration, so a burst of
 * changes costs one rewrite.
 */
static bool publish_dirty;

void
svc_reclaim_mark_dirty(void)
{
	publish_dirty = true;
}

void
svc_reclaim_publish_if_dirty(void)
{
	if (!publish_dirty)
		return;
	publish_dirty = false;
	svc_reclaim_publish_live();
}

/* "<run>/live", under the (env-overridable) Run/ directory. */
static const char *
live_dir(char *buf, size_t bufsz)
{
	if (snprintf(buf, bufsz, "%s/live", switchboard_run_dir) >= (int)bufsz)
		return (NULL);
	return (buf);
}

/* The installed bundle a running unit belongs to (Foo.cap -> Foo), or "". */
static void
bundle_of(struct svc_runtime *svc, char *out, size_t outsz)
{
	struct capbundle *b;
	const char *name;
	size_t len;

	out[0] = '\0';
	if (svc->bundle_idx == (unsigned)-1)
		return;			/* rc unit or no bundle: not a container */
	b = bundle_registry_get(svc->bundle_idx);
	if (b == NULL || (name = capbundle_name(b)) == NULL)
		return;
	(void)strlcpy(out, name, outsz);
	len = strlen(out);
	if (len > 4 && strcmp(out + len - 4, ".cap") == 0)
		out[len - 4] = '\0';
}

static bool
bundle_present(char (*set)[BUNDLE_MAX], size_t n, const char *name)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (strcmp(set[i], name) == 0)
			return (true);
	return (false);
}

/*
 * Create the marker directory.  Called before any unit launches so switchboard
 * can deliver Run/live as a directory descriptor (manifest directories = [...])
 * to providers that reconcile against the running set; Run/ is ephemeral per
 * boot, so this runs every startup.  Non-fatal: a provider that cannot get the
 * descriptor simply treats the running set as empty (installed-only live set).
 */
void
svc_reclaim_live_prepare(void)
{
	char live[PATH_MAX];

	(void)mkdir(switchboard_run_dir, 0700);
	if (live_dir(live, sizeof(live)) == NULL)
		return;
	if (mkdir(live, 0700) == -1 && errno != EEXIST)
		syslog(LOG_WARNING, "reclaim: mkdir %s: %m", live);
}

void
svc_reclaim_publish_live(void)
{
	char (*live)[BUNDLE_MAX] = NULL;
	size_t nlive = 0, cap = 0;
	unsigned i;
	int dfd;
	DIR *d;
	struct dirent *de;

	char live_path[PATH_MAX];

	publish_dirty = false;
	svc_reclaim_live_prepare();
	if (live_dir(live_path, sizeof(live_path)) == NULL)
		return;
	dfd = open(live_path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dfd == -1) {
		syslog(LOG_WARNING, "reclaim: open %s: %m", live_path);
		return;
	}

	/* 1. One marker per running unit's bundle. */
	for (i = 0; i < sd.nservices; i++) {
		struct svc_runtime *svc = &sd.services[i];
		char bundle[BUNDLE_MAX];
		int fd;

		if (svc->state != SVC_STATE_RUNNING &&
		    svc->state != SVC_STATE_STARTING)
			continue;
		bundle_of(svc, bundle, sizeof(bundle));
		if (bundle[0] == '\0' || bundle_present(live, nlive, bundle))
			continue;
		if (nlive == cap) {
			size_t ncap = cap == 0 ? 16 : cap * 2;
			void *p = reallocarray(live, ncap, sizeof(*live));

			if (p == NULL)
				break;
			live = p;
			cap = ncap;
		}
		(void)strlcpy(live[nlive++], bundle, BUNDLE_MAX);
		fd = openat(dfd, bundle, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
		if (fd != -1)
			(void)close(fd);
	}

	/* 2. Remove markers for bundles that are no longer running. */
	d = fdopendir(dfd);
	if (d != NULL) {
		while ((de = readdir(d)) != NULL) {
			if (strcmp(de->d_name, ".") == 0 ||
			    strcmp(de->d_name, "..") == 0)
				continue;
			if (!bundle_present(live, nlive, de->d_name))
				(void)unlinkat(dfd, de->d_name, 0);
		}
		(void)closedir(d);	/* also closes dfd */
	} else {
		(void)close(dfd);
	}
	SWITCHBOARD_PROBE_LIVE_PUBLISH((unsigned int)nlive);
	free(live);
	svc_reclaim_publish_groups();
}

/*
 * Publish the installed-claimed group containers as Run/groups/<group>
 * markers: one per group any INSTALLED bundle declares in its Bundle.ucl
 * `groups`.  This is the live view tzfsd's group reconcile compares
 * Data/Shared/<group>/ against (docs/capability-container-model.md: a group
 * container is an orphan only when no installed bundle still claims it).
 * Installed, not running: membership is an install-time property.
 */
void
svc_reclaim_publish_groups(void)
{
	char (*claimed)[BUNDLE_MAX] = NULL;
	char groups_path[PATH_MAX];
	size_t nclaimed = 0, cap = 0;
	unsigned bi, gi, nb;
	int dfd;
	DIR *d;
	struct dirent *de;

	if (snprintf(groups_path, sizeof(groups_path), "%s/groups",
	    switchboard_run_dir) >= (int)sizeof(groups_path))
		return;
	if (mkdir(groups_path, 0700) == -1 && errno != EEXIST) {
		syslog(LOG_WARNING, "reclaim: mkdir %s: %m", groups_path);
		return;
	}
	dfd = open(groups_path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dfd == -1)
		return;
	nb = bundle_registry_count();
	for (bi = 0; bi < nb; bi++) {
		struct capbundle *b = bundle_registry_get(bi);
		unsigned ng = capbundle_ngroups(b);

		for (gi = 0; gi < ng; gi++) {
			const char *g = capbundle_group(b, gi);
			int fd;

			if (g == NULL || g[0] == '\0' ||
			    bundle_present(claimed, nclaimed, g))
				continue;
			if (nclaimed == cap) {
				size_t ncap = cap == 0 ? 16 : cap * 2;
				void *p = reallocarray(claimed, ncap,
				    sizeof(*claimed));

				if (p == NULL)
					goto out;
				claimed = p;
				cap = ncap;
			}
			(void)strlcpy(claimed[nclaimed++], g, BUNDLE_MAX);
			fd = openat(dfd, g, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
			if (fd != -1)
				(void)close(fd);
		}
	}
	/* Drop markers for groups no installed bundle claims any more. */
	d = fdopendir(dfd);
	if (d != NULL) {
		while ((de = readdir(d)) != NULL) {
			if (strcmp(de->d_name, ".") == 0 ||
			    strcmp(de->d_name, "..") == 0)
				continue;
			if (!bundle_present(claimed, nclaimed, de->d_name))
				(void)unlinkat(dfd, de->d_name, 0);
		}
		(void)closedir(d);	/* also closes dfd */
		dfd = -1;
	}
out:
	if (dfd != -1)
		(void)close(dfd);
	free(claimed);
}
