/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Bundle registry for serviced.
 *
 * Scans /Capabilities/System/ and /Capabilities/ for .cap bundles,
 * builds a provides hash table mapping service names to bundle+service
 * indices, and validates system bundle integrity at startup.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <libcapbundle.h>

#include "serviced.h"
#include "serviced_probes.h"

#define	PROVIDES_HASH_SIZE	64

/*
 * NOTE: Duplicates bundle_name_has_suffix() in libcapbundle.c.
 * That function is static and not exported via the public API.
 * If libcapbundle exports it in the future, replace this copy.
 */
static bool
is_bundle_name(const char *name)
{
	size_t len;

	len = strlen(name);
	if (len < 4)
		return (false);
	return (strcmp(name + len - 4, ".cap") == 0);
}

static bool
trusted_tree(const char *path, char *errbuf, size_t errlen)
{
	FTS *fts;
	FTSENT *ent;
	char *paths[2];
	bool trusted;

	paths[0] = __DECONST(char *, path);
	paths[1] = NULL;
	fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		snprintf(errbuf, errlen, "%s: fts_open: %s", path,
		    strerror(errno));
		return (false);
	}
	trusted = true;
	errno = 0;
	while ((ent = fts_read(fts)) != NULL) {
		if (ent->fts_info == FTS_DP)
			continue;
		if (ent->fts_info != FTS_D && ent->fts_info != FTS_F) {
			snprintf(errbuf, errlen,
			    "%s: symlink or non-regular object is not allowed",
			    ent->fts_path);
			trusted = false;
			break;
		}
		if (ent->fts_statp->st_uid != 0 ||
		    (ent->fts_statp->st_mode & (S_IWGRP | S_IWOTH)) != 0) {
			snprintf(errbuf, errlen,
			    "%s: policy must be root-owned and not group/world-writable",
			    ent->fts_path);
			trusted = false;
			break;
		}
	}
	if (ent == NULL && errno != 0 && trusted) {
		snprintf(errbuf, errlen, "%s: traversal failed: %s", path,
		    strerror(errno));
		trusted = false;
	}
	(void)fts_close(fts);
	return (trusted);
}

struct provides_entry {
	struct provides_entry	*next;
	char			 name[CAPBUNDLE_NAME_MAX + 1];
	unsigned		 bundle_idx;
	unsigned		 service_idx;
	bool			 system;
};

struct bundle_state {
	struct capbundle	*bundle;
	bool			 system;
};

static struct bundle_state *bundles;
static unsigned nbundles;
static unsigned bundles_cap;
static struct provides_entry *provides_hash[PROVIDES_HASH_SIZE];

static unsigned
provides_hashfn(const char *s)
{

	return (serviced_hash_djb2(s) % PROVIDES_HASH_SIZE);
}

static bool
provides_exists(const char *name)
{
	struct provides_entry *e;
	for (e = provides_hash[provides_hashfn(name)]; e != NULL; e = e->next)
		if (strcmp(e->name, name) == 0)
			return (true);
	return (false);
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
scan_cb(struct capbundle *b, void *ctx)
{
	struct scan_ctx *sc = ctx;
	char errbuf[256];
	unsigned i, j;

	/* Validate bundle integrity. */
	if (capbundle_verify(b, errbuf, sizeof(errbuf)) == -1) {
		SERVICED_PROBE_MANIFEST_REJECT(capbundle_name(b), errbuf,
		    sc->system ? 1 : 0);
		syslog(LOG_ERR, "bundle_registry: %sbundle '%s' invalid: %s",
		    sc->system ? "SYSTEM " : "", capbundle_name(b), errbuf);
		capbundle_close(b);
		return (-1);
	}

	/* Grow array if needed. */
	if (nbundles >= bundles_cap) {
		unsigned newcap;
		struct bundle_state *newp;

		newcap = bundles_cap == 0 ? 16 : bundles_cap * 2;
		newp = reallocarray(bundles, newcap, sizeof(*bundles));
		if (newp == NULL) {
			syslog(LOG_ERR, "bundle_registry: realloc: %m");
			capbundle_close(b);
			return (-1);
		}
		bundles = newp;
		bundles_cap = newcap;
	}

	bundles[nbundles].bundle = b;
	bundles[nbundles].system = sc->system;
	for (i = 0; i < nbundles; i++) {
		if (strcmp(capbundle_id(b),
		    capbundle_id(bundles[i].bundle)) == 0) {
			syslog(LOG_ERR, "bundle_registry: duplicate bundle_id '%s'",
			    capbundle_id(b));
			capbundle_close(b);
			bundles[nbundles].bundle = NULL;
			return (-1);
		}
	}

	/* Check for label collisions with already-loaded bundles. */
	for (i = 0; i < capbundle_nservices(b); i++) {
		struct capbundle_service *svc = capbundle_service(b, i);
		const char *label = capbundle_svc_label(svc);
		unsigned bi2, si2;

		for (bi2 = 0; bi2 < nbundles; bi2++) {
			struct capbundle *prev = bundles[bi2].bundle;
			for (si2 = 0; si2 < capbundle_nservices(prev); si2++) {
				struct capbundle_service *ps =
				    capbundle_service(prev, si2);
				if (strcmp(label, capbundle_svc_label(ps)) == 0) {
					syslog(LOG_WARNING,
					    "bundle_registry: label '%s' in "
					    "'%s' collides with '%s'",
					    label, capbundle_name(b),
					    capbundle_name(prev));
					capbundle_close(b);
					return (-1);
				}
			}
		}
	}

	/* Register all provides names. */
	for (i = 0; i < capbundle_nservices(b); i++) {
		struct capbundle_service *svc = capbundle_service(b, i);
		unsigned np = capbundle_svc_nprovides(svc);

		for (j = 0; j < np; j++) {
			const char *name = capbundle_svc_provides(svc, j);
			if (provides_insert(name, nbundles, i,
			    sc->system) == -1) {
				capbundle_close(b);
				bundles[nbundles].bundle = NULL;
				return (-1);
			}
		}
	}

	syslog(LOG_INFO, "bundle_registry: loaded '%s' (%u services)%s",
	    capbundle_name(b), capbundle_nservices(b),
	    sc->system ? " [system]" : "");
	SERVICED_PROBE_BUNDLE_LOAD(capbundle_name(b),
	    capbundle_nservices(b), sc->system ? 1 : 0);
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
	struct capbundle *b;
	int ret;
	struct stat sb;

	if (lstat(dirpath, &sb) == -1 || !S_ISDIR(sb.st_mode) ||
	    sb.st_uid != 0 || (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		syslog(LOG_ERR, "bundle_registry: %s must be a root-owned, "
		    "non-group/world-writable directory", dirpath);
		errno = EPERM;
		return (-1);
	}

	d = opendir(dirpath);
	if (d == NULL)
		return (-1);

	ctx.system = system;
	while ((de = readdir(d)) != NULL) {
		if (!is_bundle_name(de->d_name))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);
		if (!trusted_tree(path, errbuf, sizeof(errbuf))) {
			SERVICED_PROBE_MANIFEST_REJECT(path, errbuf,
			    system ? 1 : 0);
			syslog(LOG_ERR, "bundle_registry: %sbundle '%s' "
			    "untrusted: %s", system ? "SYSTEM " : "", path,
			    errbuf);
			closedir(d);
			return (-1);
		}
		if (capbundle_open(path, &b, errbuf, sizeof(errbuf)) == -1) {
			SERVICED_PROBE_MANIFEST_REJECT(path, errbuf, system ? 1 : 0);
			syslog(LOG_ERR, "bundle_registry: %sbundle '%s' invalid: %s",
			    system ? "SYSTEM " : "", path, errbuf);
			closedir(d);
			return (-1);
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

static void
registry_dispose(struct bundle_state *state, unsigned nstate,
    struct provides_entry *hash[PROVIDES_HASH_SIZE])
{
	struct provides_entry *e, *next;
	unsigned h, i;

	for (h = 0; h < PROVIDES_HASH_SIZE; h++)
		for (e = hash[h]; e != NULL; e = next) {
			next = e->next;
			free(e);
		}
	for (i = 0; i < nstate; i++)
		capbundle_close(state[i].bundle);
	free(state);
}

/*
 * Initialize the bundle registry.
 * Scans system and user bundle directories.
 * The replacement is built transactionally.  On failure the previous
 * registry remains available to running and on-demand services.
 */
int
bundle_registry_init(void)
{
	struct bundle_state *old_bundles;
	struct provides_entry *old_hash[PROVIDES_HASH_SIZE];
	char errbuf[512];
	struct stat sb;
	struct capbundle **cycle_bundles;
	unsigned i, old_nbundles, old_bundles_cap, nservices;
	int cycle_ret;

	old_bundles = bundles;
	old_nbundles = nbundles;
	old_bundles_cap = bundles_cap;
	memcpy(old_hash, provides_hash, sizeof(old_hash));
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
			goto fail;
		}
	} else {
		syslog(LOG_INFO,
		    "bundle_registry: %s not found, skipping",
		    serviced_bundle_dir_system);
	}

	/* User bundle directory is optional; malformed bundles are fatal. */
	if (stat(serviced_bundle_dir_user, &sb) == 0 &&
	    S_ISDIR(sb.st_mode)) {
		if (scan_bundle_dir(serviced_bundle_dir_user, false) == -1) {
			syslog(LOG_ERR,
			    "bundle_registry: user bundle scan failed");
			goto fail;
		}
	} else {
		syslog(LOG_INFO,
		    "bundle_registry: %s not found, skipping",
		    serviced_bundle_dir_user);
	}

	if (nbundles == 0) {
		syslog(LOG_WARNING, "bundle_registry: no bundles loaded");
		registry_dispose(old_bundles, old_nbundles, old_hash);
		return (0);
	}
	nservices = 0;
	for (i = 0; i < nbundles; i++) {
		nservices += capbundle_nservices(bundles[i].bundle);
		if (nservices > SERVICED_MAX_SERVICES) {
			syslog(LOG_CRIT,
			    "bundle_registry: %u services exceeds limit %u",
			    nservices, SERVICED_MAX_SERVICES);
			goto fail;
		}
	}
	for (i = 0; i < nbundles; i++) {
		unsigned si, ri;
		struct capbundle *b = bundles[i].bundle;
		for (si = 0; si < capbundle_nservices(b); si++) {
			struct capbundle_service *svc = capbundle_service(b, si);
			struct svc_manifest manifest;

			if (capbundle_svc_fill_manifest(svc, &manifest) == -1) {
				syslog(LOG_CRIT,
				    "bundle_registry: invalid service manifest %s",
				    capbundle_svc_label(svc));
				goto fail;
			}
			for (ri = 0; ri < manifest.nstartup_after; ri++) {
				const char *provider =
				    manifest.startup_after[ri];
				if (strcmp(provider, "ORACLED") != 0 &&
				    !provides_exists(provider)) {
					syslog(LOG_CRIT,
					    "bundle_registry: %s has unknown startup provider %s",
					    capbundle_svc_label(svc), provider);
					SERVICED_PROBE_MANIFEST_REJECT(
					    capbundle_name(b), "unknown provider",
					    bundles[i].system ? 1 : 0);
					goto fail;
				}
			}
		}
	}

	/*
	 * Cross-bundle circular dependency check.  Size the working array
	 * from the actual bundle count — a previous fixed 128-entry cap
	 * silently skipped cycles involving any bundle past index 128 while
	 * still reporting the graph acyclic.
	 */
	cycle_bundles = reallocarray(NULL, nbundles, sizeof(*cycle_bundles));
	if (cycle_bundles == NULL) {
		syslog(LOG_CRIT,
		    "bundle_registry: out of memory for cycle check — "
		    "cannot start");
		goto fail;
	}
	for (i = 0; i < nbundles; i++)
		cycle_bundles[i] = bundles[i].bundle;

	cycle_ret = capbundle_check_startup_cycles(cycle_bundles, nbundles,
	    errbuf, sizeof(errbuf));
	free(cycle_bundles);
	if (cycle_ret == -1) {
		syslog(LOG_CRIT,
		    "bundle_registry: %s — cannot start", errbuf);
		goto fail;
	}

	syslog(LOG_INFO,
	    "bundle_registry: %u bundles loaded, dependency graph acyclic",
	    nbundles);
	SERVICED_PROBE_BUNDLE_SCAN("all", nbundles);
	registry_dispose(old_bundles, old_nbundles, old_hash);
	return (0);

fail:
	registry_dispose(bundles, nbundles, provides_hash);
	bundles = old_bundles;
	nbundles = old_nbundles;
	bundles_cap = old_bundles_cap;
	memcpy(provides_hash, old_hash, sizeof(provides_hash));
	return (-1);
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
struct capbundle *
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
 * Activation policy is a serviced property, not a manifest knob.
 * Ordinary named providers start on first lookup.  The two local component
 * factories start during bootstrap because their endpoints must exist before
 * a consumer can be executed in capability mode.
 */
bool
bundle_service_activates_on_lookup(const struct capbundle_service *service)
{
	const char *name;
	unsigned i;

	if (capbundle_svc_nprovides(service) == 0)
		return (false);
	for (i = 0; i < capbundle_svc_nprovides(service); i++) {
		name = capbundle_svc_provides(service, i);
		if (strcmp(name, "org.5bsd.FileSystemCmp") == 0 ||
		    strcmp(name, "org.5bsd.NetworkCmp") == 0)
			return (false);
	}
	return (true);
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
	registry_dispose(bundles, nbundles, provides_hash);
	memset(provides_hash, 0, sizeof(provides_hash));
	bundles = NULL;
	nbundles = 0;
	bundles_cap = 0;
}
