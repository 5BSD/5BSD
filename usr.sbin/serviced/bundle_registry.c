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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <libcapbundle.h>

#include "bundle_selection.h"
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

/*
 * Operator disable list.  Reloaded from SERVICED_DISABLED_PATH at the start of
 * every registry (re)build so servicectl enable/disable takes effect on the
 * next reload.  An installed but disabled bundle is skipped: it neither
 * reserves names nor runs, but stays on disk to re-enable without reinstall.
 */
static char **disabled_ids;
static unsigned ndisabled;

static void
disabled_set_clear(void)
{
	unsigned i;

	for (i = 0; i < ndisabled; i++)
		free(disabled_ids[i]);
	free(disabled_ids);
	disabled_ids = NULL;
	ndisabled = 0;
}

/* Resolve the disable-list path: env override wins, else the plane default. */
static const char *
disabled_path(void)
{
	const char *env = getenv("SERVICED_DISABLED_PATH");

	return ((env != NULL && env[0] != '\0') ? env : SERVICED_DISABLED_PATH);
}

static void
disabled_set_load(void)
{
	FILE *f;
	char *line = NULL;
	char path[PATH_MAX];
	size_t cap = 0;
	char **np;

	disabled_set_clear();
	/*
	 * The disable list is pre-storage bootstrap state: serviced reads it
	 * while building the registry, before tzfsd provisions any runtime
	 * home, so it lives in the minimal static Config/ area rather than a
	 * per-capability home (see docs: capability filesystem hierarchy).
	 * SERVICED_DISABLED_PATH in the environment redirects it for tests.
	 */
	if (strlcpy(path, disabled_path(), sizeof(path)) >= sizeof(path))
		return;
	f = fopen(path, "re");
	if (f == NULL)
		return;
	while (getline(&line, &cap, f) != -1) {
		char *s = line;

		while (*s == ' ' || *s == '\t')
			s++;
		s[strcspn(s, " \t\r\n")] = '\0';
		if (*s == '\0' || *s == '#')
			continue;
		np = reallocarray(disabled_ids, ndisabled + 1,
		    sizeof(*disabled_ids));
		if (np == NULL)
			break;
		disabled_ids = np;
		disabled_ids[ndisabled] = strdup(s);
		if (disabled_ids[ndisabled] == NULL)
			break;
		ndisabled++;
	}
	free(line);
	fclose(f);
}

static bool
bundle_is_disabled(const char *id)
{
	unsigned i;

	for (i = 0; i < ndisabled; i++)
		if (strcmp(disabled_ids[i], id) == 0)
			return (true);
	return (false);
}

static int
scan_cb(struct capbundle *b, void *ctx)
{
	struct scan_ctx *sc = ctx;
	char errbuf[256];
	unsigned i;
	enum bundle_selection_result selection;

	/* Validate bundle integrity. */
	if (capbundle_verify(b, errbuf, sizeof(errbuf)) == -1) {
		SERVICED_PROBE_MANIFEST_REJECT(capbundle_name(b), errbuf,
		    sc->system ? 1 : 0);
		syslog(LOG_ERR, "bundle_registry: %sbundle '%s' invalid: %s",
		    sc->system ? "SYSTEM " : "", capbundle_name(b), errbuf);
		capbundle_close(b);
		return (-1);
	}

	/* Skip an operator-disabled bundle: installed, but not registered. */
	if (bundle_is_disabled(capbundle_id(b))) {
		syslog(LOG_INFO, "bundle_registry: %sbundle '%s' disabled by "
		    "operator, skipping", sc->system ? "SYSTEM " : "",
		    capbundle_id(b));
		capbundle_close(b);
		return (0);
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

	/*
	 * Installed versions are immutable directories named by identity and
	 * sequence.  Keep exactly the highest sequence for a bundle identity.
	 * A user bundle may never shadow a system bundle with the same identity.
	 */
	for (i = 0; i < nbundles; i++) {
		selection = bundle_selection_compare(
		    capbundle_id(bundles[i].bundle),
		    capbundle_sequence(bundles[i].bundle), bundles[i].system,
		    capbundle_id(b), capbundle_sequence(b), sc->system);
		if (selection != BUNDLE_SELECTION_DISTINCT) {
			if (selection == BUNDLE_SELECTION_ORIGIN_CONFLICT) {
				syslog(LOG_ERR,
				    "bundle_registry: user bundle may not shadow system bundle_id '%s'",
				    capbundle_id(b));
				capbundle_close(b);
				return (-1);
			}
			if (selection == BUNDLE_SELECTION_SEQUENCE_CONFLICT ||
			    selection == BUNDLE_SELECTION_INVALID) {
				syslog(LOG_ERR,
				    "bundle_registry: duplicate sequence %ju for bundle_id '%s'",
				    (uintmax_t)capbundle_sequence(b), capbundle_id(b));
				capbundle_close(b);
				return (-1);
			}
			if (selection == BUNDLE_SELECTION_KEEP_CURRENT) {
				syslog(LOG_INFO,
				    "bundle_registry: retaining newer '%s' sequence %ju over %ju",
				    capbundle_id(b),
				    (uintmax_t)capbundle_sequence(bundles[i].bundle),
				    (uintmax_t)capbundle_sequence(b));
				capbundle_close(b);
				return (0);
			}
			if (selection != BUNDLE_SELECTION_REPLACE_CURRENT) {
				capbundle_close(b);
				return (-1);
			}
			syslog(LOG_INFO,
			    "bundle_registry: selecting '%s' sequence %ju over %ju",
			    capbundle_id(b), (uintmax_t)capbundle_sequence(b),
			    (uintmax_t)capbundle_sequence(bundles[i].bundle));
			capbundle_close(bundles[i].bundle);
			bundles[i].bundle = b;
			return (0);
		}
	}
	bundles[nbundles].bundle = b;
	bundles[nbundles].system = sc->system;
	syslog(LOG_INFO, "bundle_registry: loaded '%s' (%u services)%s",
	    capbundle_name(b), capbundle_nservices(b),
	    sc->system ? " [system]" : "");
	SERVICED_PROBE_BUNDLE_LOAD(capbundle_name(b),
	    capbundle_nservices(b), sc->system ? 1 : 0);
	nbundles++;
	return (0);  /* continue scanning */
}

/* Build name indexes only after version selection is complete. */
static int
registry_build_indexes(void)
{
	unsigned bi, si, bj, sj, pi;

	for (bi = 0; bi < nbundles; bi++) {
		struct capbundle *b = bundles[bi].bundle;

		for (si = 0; si < capbundle_nservices(b); si++) {
			struct capbundle_service *svc = capbundle_service(b, si);
			const char *label = capbundle_svc_label(svc);

			for (bj = 0; bj <= bi; bj++) {
				struct capbundle *other = bundles[bj].bundle;
				unsigned limit = bj == bi ? si :
				    capbundle_nservices(other);

				for (sj = 0; sj < limit; sj++) {
					if (strcmp(label, capbundle_svc_label(
					    capbundle_service(other, sj))) == 0) {
						syslog(LOG_ERR,
						    "bundle_registry: duplicate unit label '%s'",
						    label);
						return (-1);
					}
				}
			}
			for (pi = 0; pi < capbundle_svc_nprovides(svc); pi++)
				if (provides_insert(capbundle_svc_provides(svc, pi),
				    bi, si, bundles[bi].system) == -1)
					return (-1);
		}
	}
	return (0);
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
			/*
			 * An untrusted or malformed base-system bundle is a boot
			 * convergence failure — continuing could silently omit
			 * required authority.  A local (user) bundle is instead
			 * quarantined: it cannot reserve names or run, but it
			 * never displaces the valid active registry (plan §15).
			 */
			if (system) {
				closedir(d);
				return (-1);
			}
			syslog(LOG_WARNING, "bundle_registry: quarantined "
			    "user bundle '%s'", path);
			continue;
		}
		if (capbundle_open(path, &b, errbuf, sizeof(errbuf)) == -1) {
			SERVICED_PROBE_MANIFEST_REJECT(path, errbuf, system ? 1 : 0);
			syslog(LOG_ERR, "bundle_registry: %sbundle '%s' invalid: %s",
			    system ? "SYSTEM " : "", path, errbuf);
			if (system) {
				closedir(d);
				return (-1);
			}
			syslog(LOG_WARNING, "bundle_registry: quarantined "
			    "user bundle '%s'", path);
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
	struct provides_entry **old_hash;
	struct svc_manifest *manifest;
	struct stat *sb;
	unsigned i, old_nbundles, old_bundles_cap, nservices;

	/*
	 * Keep all caller-owned buffers off the daemon stack.  Apart from the
	 * manifest being large, the parser is an independent trust boundary: a
	 * bounds bug in it must not be able to overwrite this function's return
	 * state or stack-protector canary.
	 */
	manifest = calloc(1, sizeof(*manifest));
	old_hash = calloc(PROVIDES_HASH_SIZE, sizeof(*old_hash));
	sb = calloc(1, sizeof(*sb));
	if (manifest == NULL || old_hash == NULL || sb == NULL) {
		syslog(LOG_CRIT,
		    "bundle_registry: out of memory for registry validation");
		free(old_hash);
		free(sb);
		free(manifest);
		return (-1);
	}
	/* Refresh the operator disable list before (re)scanning. */
	disabled_set_load();

	old_bundles = bundles;
	old_nbundles = nbundles;
	old_bundles_cap = bundles_cap;
	memcpy(old_hash, provides_hash, sizeof(provides_hash));
	memset(provides_hash, 0, sizeof(provides_hash));
	nbundles = 0;
	bundles_cap = 0;
	bundles = NULL;

	/* System bundles: optional.  Missing directory is not fatal — the
	 * system may be running without application bundles (e.g., tests,
	 * embedded, or early boot before the filesystem is populated). */
	if (stat(serviced_bundle_dir_system, sb) == 0 &&
	    S_ISDIR(sb->st_mode)) {
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
	if (stat(serviced_bundle_dir_user, sb) == 0 &&
	    S_ISDIR(sb->st_mode)) {
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
		free(old_hash);
		free(sb);
		free(manifest);
		return (0);
	}
	if (registry_build_indexes() == -1)
		goto fail;
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
		unsigned si;
		struct capbundle *b = bundles[i].bundle;
		for (si = 0; si < capbundle_nservices(b); si++) {
			struct capbundle_service *svc = capbundle_service(b, si);

			if (capbundle_svc_fill_manifest(svc, manifest) == -1) {
				syslog(LOG_CRIT,
				    "bundle_registry: invalid service manifest %s",
				    capbundle_svc_label(svc));
				goto fail;
			}
		}
	}

	syslog(LOG_INFO, "bundle_registry: %u bundles loaded", nbundles);
	SERVICED_PROBE_BUNDLE_SCAN("all", nbundles);
	registry_dispose(old_bundles, old_nbundles, old_hash);
	free(old_hash);
	free(sb);
	free(manifest);
	return (0);

fail:
	free(manifest);
	registry_dispose(bundles, nbundles, provides_hash);
	bundles = old_bundles;
	nbundles = old_nbundles;
	bundles_cap = old_bundles_cap;
	memcpy(provides_hash, old_hash, sizeof(provides_hash));
	free(old_hash);
	free(sb);
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
 * Is `label` a currently-installed bundle's manifest label?
 *
 * The authoritative liveness test behind SVC_OP_LABEL_IS_LIVE
 * (docs/capability-lifecycle-cleanup.md).  A label is live iff
 * some registered bundle declares a service with exactly that label.  This is a
 * pure read over the active registry; an operator-disabled or uninstalled
 * bundle is not registered and therefore is not live.  Labels are unique across
 * the registry (enforced by registry_build_indexes), so a linear scan suffices
 * and terminates on the first match.
 */
bool
bundle_registry_label_installed(const char *label)
{
	unsigned bi, si;
	struct capbundle *b;
	struct capbundle_service *svc;

	if (label == NULL || label[0] == '\0')
		return (false);
	for (bi = 0; bi < nbundles; bi++) {
		b = bundles[bi].bundle;
		for (si = 0; si < capbundle_nservices(b); si++) {
			svc = capbundle_service(b, si);
			if (svc != NULL &&
			    strcmp(capbundle_svc_label(svc), label) == 0)
				return (true);
		}
	}
	return (false);
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
