/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Bundle registry for serviced.
 *
 * Scans /System/Applications/ and /Applications/ for .app bundles,
 * builds a provides hash table mapping service names to bundle+service
 * indices, and validates system bundle integrity at startup.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <libappbundle.h>

#include "serviced.h"
#include "serviced_probes.h"

#define	PROVIDES_HASH_SIZE	64

struct provides_entry {
	struct provides_entry	*next;
	char			 name[APPBUNDLE_NAME_MAX + 1];
	unsigned		 bundle_idx;
	unsigned		 service_idx;
	bool			 system;
};

struct bundle_state {
	struct appbundle	*bundle;
	bool			 system;
};

static struct bundle_state *bundles;
static unsigned nbundles;
static unsigned bundles_cap;
static struct provides_entry *provides_hash[PROVIDES_HASH_SIZE];

/*
 * DJB2 hash (matches naming.c).
 */
static unsigned
provides_hashfn(const char *s)
{
	unsigned long h;

	h = 5381;
	while (*s != '\0')
		h = h * 33 + (unsigned char)*s++;
	return ((unsigned)(h % PROVIDES_HASH_SIZE));
}

/*
 * Insert a provides entry into the hash table.
 * Returns 0 on success, -1 if duplicate (logs warning).
 */
static int
provides_insert(const char *name, unsigned bundle_idx, unsigned service_idx,
    bool system)
{
	unsigned h;
	struct provides_entry *e;

	h = provides_hashfn(name);

	/* Check for duplicates. */
	for (e = provides_hash[h]; e != NULL; e = e->next) {
		if (strcmp(e->name, name) == 0) {
			syslog(LOG_WARNING,
			    "bundle_registry: duplicate provides '%s' "
			    "(bundle %u vs %u)", name,
			    e->bundle_idx, bundle_idx);
			return (-1);
		}
	}

	e = calloc(1, sizeof(*e));
	if (e == NULL)
		return (-1);

	strlcpy(e->name, name, sizeof(e->name));
	e->bundle_idx = bundle_idx;
	e->service_idx = service_idx;
	e->system = system;
	e->next = provides_hash[h];
	provides_hash[h] = e;
	return (0);
}

/*
 * Scan callback: collect bundles into the global array.
 */
struct scan_ctx {
	bool system;
};

static int
scan_cb(struct appbundle *b, void *ctx)
{
	struct scan_ctx *sc = ctx;
	char errbuf[256];
	unsigned i, j;

	/* Validate bundle integrity. */
	if (appbundle_verify(b, errbuf, sizeof(errbuf)) == -1) {
		if (sc->system) {
			syslog(LOG_ERR,
			    "bundle_registry: SYSTEM bundle '%s' invalid: %s",
			    appbundle_name(b), errbuf);
			appbundle_close(b);
			return (-1);  /* fatal for system bundles */
		}
		syslog(LOG_WARNING,
		    "bundle_registry: skipping '%s': %s",
		    appbundle_name(b), errbuf);
		appbundle_close(b);
		return (0);  /* non-fatal for user bundles */
	}

	/* Grow array if needed. */
	if (nbundles >= bundles_cap) {
		unsigned newcap;
		struct bundle_state *newp;

		newcap = bundles_cap == 0 ? 16 : bundles_cap * 2;
		newp = reallocarray(bundles, newcap, sizeof(*bundles));
		if (newp == NULL) {
			syslog(LOG_ERR, "bundle_registry: realloc: %m");
			appbundle_close(b);
			return (-1);
		}
		bundles = newp;
		bundles_cap = newcap;
	}

	bundles[nbundles].bundle = b;
	bundles[nbundles].system = sc->system;

	/* Check for label collisions with already-loaded bundles. */
	for (i = 0; i < appbundle_nservices(b); i++) {
		struct appbundle_service *svc = appbundle_service(b, i);
		const char *label = appbundle_svc_label(svc);
		unsigned bi2, si2;

		for (bi2 = 0; bi2 < nbundles; bi2++) {
			struct appbundle *prev = bundles[bi2].bundle;
			for (si2 = 0; si2 < appbundle_nservices(prev); si2++) {
				struct appbundle_service *ps =
				    appbundle_service(prev, si2);
				if (strcmp(label, appbundle_svc_label(ps)) == 0) {
					syslog(LOG_WARNING,
					    "bundle_registry: label '%s' in "
					    "'%s' collides with '%s'",
					    label, appbundle_name(b),
					    appbundle_name(prev));
					if (sc->system) {
						appbundle_close(b);
						return (-1);
					}
					/* Skip the entire user bundle. */
					appbundle_close(b);
					return (0);
				}
			}
		}
	}

	/* Register all provides names. */
	for (i = 0; i < appbundle_nservices(b); i++) {
		struct appbundle_service *svc = appbundle_service(b, i);
		unsigned np = appbundle_svc_nprovides(svc);

		for (j = 0; j < np; j++) {
			const char *name = appbundle_svc_provides(svc, j);
			if (provides_insert(name, nbundles, i,
			    sc->system) == -1 && sc->system) {
				/* Duplicate in system bundle = fatal. */
				return (-1);
			}
		}
	}

	syslog(LOG_INFO, "bundle_registry: loaded '%s' (%u services)%s",
	    appbundle_name(b), appbundle_nservices(b),
	    sc->system ? " [system]" : "");
	SERVICED_PROBE_BUNDLE_LOAD(appbundle_name(b),
	    appbundle_nservices(b), sc->system ? 1 : 0);
	nbundles++;
	return (0);  /* continue scanning */
}

static int
scan_bundle_dir(const char *dirpath, bool system)
{
	struct scan_ctx ctx;
	DIR *d;
	struct dirent *de;
	char path[PATH_MAX];
	char errbuf[256];
	struct appbundle *b;
	size_t len;
	int ret;

	d = opendir(dirpath);
	if (d == NULL)
		return (-1);

	ctx.system = system;
	while ((de = readdir(d)) != NULL) {
		len = strlen(de->d_name);
		if (len < 5 || strcmp(de->d_name + len - 4, ".app") != 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);
		if (appbundle_open(path, &b, errbuf, sizeof(errbuf)) == -1) {
			if (system) {
				syslog(LOG_ERR,
				    "bundle_registry: SYSTEM bundle '%s' "
				    "invalid: %s", path, errbuf);
				closedir(d);
				return (-1);
			}
			syslog(LOG_WARNING,
			    "bundle_registry: skipping '%s': %s",
			    path, errbuf);
			continue;
		}

		ret = scan_cb(b, &ctx);
		if (ret != 0) {
			closedir(d);
			return (ret);
		}
	}

	closedir(d);
	return (0);
}

/*
 * Initialize the bundle registry.
 * Scans system and user bundle directories.
 * Returns 0 on success, -1 on fatal error (system bundle issues).
 */
int
bundle_registry_init(void)
{
	char errbuf[512];
	struct stat sb;
	struct appbundle *cycle_bundles[128];
	unsigned i;

	memset(provides_hash, 0, sizeof(provides_hash));
	nbundles = 0;
	bundles_cap = 0;
	bundles = NULL;

	/* System bundles: optional.  Missing directory is not fatal — the
	 * system may be running without application bundles (e.g., tests,
	 * embedded, or early boot before the filesystem is populated). */
	if (stat(serviced_bundle_dir_system, &sb) == 0 &&
	    S_ISDIR(sb.st_mode)) {
		if (scan_bundle_dir(serviced_bundle_dir_system, true) == -1) {
			syslog(LOG_ERR,
			    "bundle_registry: system bundle scan failed");
			return (-1);
		}
	} else {
		syslog(LOG_INFO,
		    "bundle_registry: %s not found, skipping",
		    serviced_bundle_dir_system);
	}

	/* User bundles: optional, errors are non-fatal. */
	if (stat(serviced_bundle_dir_user, &sb) == 0 &&
	    S_ISDIR(sb.st_mode)) {
		(void)scan_bundle_dir(serviced_bundle_dir_user, false);
	} else {
		syslog(LOG_INFO,
		    "bundle_registry: %s not found, skipping",
		    serviced_bundle_dir_user);
	}

	if (nbundles == 0) {
		syslog(LOG_WARNING, "bundle_registry: no bundles loaded");
		return (0);
	}

	/* Cross-bundle circular dependency check. */
	for (i = 0; i < nbundles && i < 128; i++)
		cycle_bundles[i] = bundles[i].bundle;

	if (appbundle_check_cycles(cycle_bundles,
	    nbundles > 128 ? 128 : nbundles,
	    errbuf, sizeof(errbuf)) == -1) {
		syslog(LOG_CRIT,
		    "bundle_registry: %s — cannot start", errbuf);
		return (-1);
	}

	syslog(LOG_INFO,
	    "bundle_registry: %u bundles loaded, dependency graph acyclic",
	    nbundles);
	SERVICED_PROBE_BUNDLE_SCAN("all", nbundles);
	return (0);
}

/*
 * Look up a provides name in the registry.
 * Returns the bundle and service indices, or -1 if not found.
 */
int
bundle_registry_lookup(const char *name, unsigned *bundle_idx_out,
    unsigned *service_idx_out)
{
	unsigned h;
	struct provides_entry *e;

	h = provides_hashfn(name);
	for (e = provides_hash[h]; e != NULL; e = e->next) {
		if (strcmp(e->name, name) == 0) {
			*bundle_idx_out = e->bundle_idx;
			*service_idx_out = e->service_idx;
			return (0);
		}
	}
	return (-1);
}

/*
 * Get a bundle by index.
 */
struct appbundle *
bundle_registry_get(unsigned idx)
{

	if (idx >= nbundles)
		return (NULL);
	return (bundles[idx].bundle);
}

/*
 * Check if a bundle is a system bundle.
 */
bool
bundle_registry_is_system(unsigned idx)
{

	if (idx >= nbundles)
		return (false);
	return (bundles[idx].system);
}

/*
 * Get total number of registered bundles.
 */
unsigned
bundle_registry_count(void)
{

	return (nbundles);
}

/*
 * Teardown: close all bundles and free the registry.
 */
void
bundle_registry_teardown(void)
{
	unsigned h, i;
	struct provides_entry *e, *next;

	for (h = 0; h < PROVIDES_HASH_SIZE; h++) {
		for (e = provides_hash[h]; e != NULL; e = next) {
			next = e->next;
			free(e);
		}
		provides_hash[h] = NULL;
	}

	for (i = 0; i < nbundles; i++)
		appbundle_close(bundles[i].bundle);

	free(bundles);
	bundles = NULL;
	nbundles = 0;
	bundles_cap = 0;
}
