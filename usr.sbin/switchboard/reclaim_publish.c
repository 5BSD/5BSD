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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "switchboard.h"

#define	RUN_DIR		"/Capabilities/Run"
#define	RUN_LIVE_DIR	"/Capabilities/Run/live"	/* running-bundle markers */
#define	BUNDLE_MAX	64

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

void
svc_reclaim_publish_live(void)
{
	char (*live)[BUNDLE_MAX] = NULL;
	size_t nlive = 0, cap = 0;
	unsigned i;
	int dfd;
	DIR *d;
	struct dirent *de;

	/* Run/ is ephemeral (cleared each boot); create the marker subdir. */
	(void)mkdir(RUN_DIR, 0700);
	if (mkdir(RUN_LIVE_DIR, 0700) == -1 && errno != EEXIST) {
		syslog(LOG_WARNING, "reclaim: mkdir %s: %m", RUN_LIVE_DIR);
		return;
	}
	dfd = open(RUN_LIVE_DIR, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (dfd == -1) {
		syslog(LOG_WARNING, "reclaim: open %s: %m", RUN_LIVE_DIR);
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
	free(live);
}
