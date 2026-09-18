/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Bundle registry for switchboard.
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
#include "switchboard.h"
#include "switchboard_probes.h"

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
	/*
	 * A registration carried forward from the previous registry because
	 * its directory failed validation mid-rescan (an in-place upgrade in
	 * progress): the on-disk bundle is stale until a later rescan reads it
	 * whole.  -1 == read from disk this scan.
	 */
	int			 carried_from;
};

static struct bundle_state *bundles;
static unsigned nbundles;
static unsigned bundles_cap;
static struct provides_entry *provides_hash[PROVIDES_HASH_SIZE];

/* Bundles skipped by the last scan as untrusted or malformed. */
static unsigned nquarantined;
/*
 * Set once a registry has been established (the boot scan succeeded).  While
 * a rescan runs, the registry it is replacing is visible here so a rejected
 * bundle can be told apart as previously-registered or new.
 */
static bool registry_established;
static struct bundle_state *prev_bundles;
static unsigned nprev_bundles;

/*
 * The previous registry's entry for this bundle directory, or -1.  Paths are
 * compared canonical to canonical (capbundle_open stores realpath(3) and
 * scan_bundle_dir builds paths from the canonical root), with the
 * (origin, name) pair as the fallback so a root spelled differently between
 * two runs never turns a registered bundle into a "new" one.
 */
static int
previous_entry(const char *path, bool system)
{
	const char *slash = strrchr(path, '/');
	const char *name = slash != NULL ? slash + 1 : path;
	unsigned i;

	for (i = 0; i < nprev_bundles; i++) {
		const struct capbundle *pb = prev_bundles[i].bundle;

		if (pb == NULL || prev_bundles[i].system != system)
			continue;
		if (strcmp(capbundle_path(pb), path) == 0 ||
		    strcmp(capbundle_name(pb), name) == 0)
			return ((int)i);
	}
	return (-1);
}

static int registry_append(struct capbundle *b, bool system, int carried_from);

/*
 * A bundle directory failed validation (untrusted tree, unparsable, or
 * failed verification).  Three outcomes:
 *
 *  - At boot (no registry yet) a malformed SYSTEM bundle is a convergence
 *    failure (-1: switchboard does not start); a user bundle is quarantined.
 *  - On a rescan, a bundle that was REGISTERED before keeps its previous
 *    registration, carried forward and marked stale (0): its units are never
 *    stopped and its markers never dropped because an in-place upgrade was
 *    caught half written -- System and Apps alike.  It is counted as
 *    quarantined so the install-folder watch rescans a bounded number of
 *    settled times and reads the finished bundle.
 *  - On a rescan, a bundle NOT registered before (a package still extracting,
 *    or a broken one that never loaded) is quarantined (0): skipped and
 *    counted, never holding the other bundles hostage.
 *
 * Failing the whole scan is reserved for errors of the scan itself.
 */
static int
reject_bundle(const char *path, bool system)
{
	int pi;

	if (!registry_established) {
		if (system)
			return (-1);
		nquarantined++;
		syslog(LOG_WARNING, "bundle_registry: quarantined bundle '%s'",
		    path);
		return (0);
	}
	pi = previous_entry(path, system);
	if (pi >= 0) {
		struct capbundle *pb = prev_bundles[pi].bundle;

		if (registry_append(pb, system, pi) == -1)
			return (-1);
		/* the previous registry no longer owns it; see fail: */
		prev_bundles[pi].bundle = NULL;
		nquarantined++;
		syslog(LOG_WARNING, "bundle_registry: %sbundle '%s' unreadable "
		    "mid-rescan; previous registration retained (stale) until "
		    "it reads whole", system ? "SYSTEM " : "", path);
		return (0);
	}
	nquarantined++;
	syslog(LOG_WARNING, "bundle_registry: quarantined %sbundle '%s'",
	    system ? "SYSTEM " : "", path);
	return (0);
}

static unsigned
provides_hashfn(const char *s)
{

	return (switchboard_hash_djb2(s) % PROVIDES_HASH_SIZE);
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
 * Operator disable list.  Reloaded from SWITCHBOARD_DISABLED_PATH at the start of
 * every registry (re)build so switchboardctl enable/disable takes effect on the
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
	const char *env = getenv("SWITCHBOARD_DISABLED_PATH");

	return ((env != NULL && env[0] != '\0') ? env : SWITCHBOARD_DISABLED_PATH);
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
	 * The disable list is pre-storage bootstrap state: switchboard reads it
	 * while building the registry, before tzfsd provisions any runtime
	 * home, so it lives in the minimal static Config/ area rather than a
	 * per-capability home (see docs: capability filesystem hierarchy).
	 * SWITCHBOARD_DISABLED_PATH in the environment redirects it for tests.
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

	/* Validate bundle integrity. */
	if (capbundle_verify(b, errbuf, sizeof(errbuf)) == -1) {
		SWITCHBOARD_PROBE_MANIFEST_REJECT(capbundle_name(b), errbuf,
		    sc->system ? 1 : 0);
		syslog(LOG_ERR, "bundle_registry: %sbundle '%s' invalid: %s",
		    sc->system ? "SYSTEM " : "", capbundle_name(b), errbuf);
		{
			char path[PATH_MAX];

			strlcpy(path, capbundle_path(b), sizeof(path));
			capbundle_close(b);
			return (reject_bundle(path, sc->system));
		}
	}


	/* Skip an operator-disabled bundle: installed, but not registered. */
	if (bundle_is_disabled(capbundle_id(b))) {
		syslog(LOG_INFO, "bundle_registry: %sbundle '%s' disabled by "
		    "operator, skipping", sc->system ? "SYSTEM " : "",
		    capbundle_id(b));
		capbundle_close(b);
		return (0);
	}

	return (registry_append(b, sc->system, -1));
}

/* Release a new-array entry: a carried bundle goes back to the previous
 * registry (it still owns it on the fail path), a scanned one is closed. */
static void
entry_release(struct bundle_state *e)
{
	if (e->bundle == NULL)
		return;
	if (e->carried_from >= 0 && prev_bundles != NULL)
		prev_bundles[e->carried_from].bundle = e->bundle;
	else
		capbundle_close(e->bundle);
	e->bundle = NULL;
}

/*
 * Add a parsed, verified (or carried) bundle to the registry being built.
 * Installed versions are immutable directories named by identity and
 * sequence: keep exactly the highest sequence for a bundle identity, and a
 * user bundle may never shadow a system bundle with the same identity.
 * A user bundle that conflicts is quarantined (it never displaces the valid
 * registry and never fails the scan); a conflicting SYSTEM bundle fails the
 * scan (a base-system packaging error, corrected by hand).
 */
static int
registry_append(struct capbundle *b, bool system, int carried_from)
{
	struct bundle_state e = { .bundle = b, .system = system,
	    .carried_from = carried_from };
	enum bundle_selection_result selection;
	unsigned i;

	/* Grow array if needed. */
	if (nbundles >= bundles_cap) {
		unsigned newcap;
		struct bundle_state *newp;

		newcap = bundles_cap == 0 ? 16 : bundles_cap * 2;
		newp = reallocarray(bundles, newcap, sizeof(*bundles));
		if (newp == NULL) {
			syslog(LOG_ERR, "bundle_registry: realloc: %m");
			entry_release(&e);
			return (-1);
		}
		bundles = newp;
		bundles_cap = newcap;
	}

	for (i = 0; i < nbundles; i++) {
		selection = bundle_selection_compare(
		    capbundle_id(bundles[i].bundle),
		    capbundle_sequence(bundles[i].bundle), bundles[i].system,
		    capbundle_id(b), capbundle_sequence(b), system);
		if (selection == BUNDLE_SELECTION_DISTINCT)
			continue;
		if (selection == BUNDLE_SELECTION_KEEP_CURRENT) {
			syslog(LOG_INFO,
			    "bundle_registry: retaining newer '%s' sequence %ju over %ju",
			    capbundle_id(b),
			    (uintmax_t)capbundle_sequence(bundles[i].bundle),
			    (uintmax_t)capbundle_sequence(b));
			entry_release(&e);
			return (0);
		}
		if (selection == BUNDLE_SELECTION_REPLACE_CURRENT) {
			syslog(LOG_INFO,
			    "bundle_registry: selecting '%s' sequence %ju over %ju",
			    capbundle_id(b), (uintmax_t)capbundle_sequence(b),
			    (uintmax_t)capbundle_sequence(bundles[i].bundle));
			entry_release(&bundles[i]);
			bundles[i] = e;
			return (0);
		}
		/* ORIGIN_CONFLICT, SEQUENCE_CONFLICT, INVALID, or unknown */
		syslog(LOG_ERR, "bundle_registry: %sbundle '%s' conflicts with "
		    "'%s' (bundle_id '%s'%s)", system ? "SYSTEM " : "",
		    capbundle_name(b), capbundle_name(bundles[i].bundle),
		    capbundle_id(b),
		    selection == BUNDLE_SELECTION_ORIGIN_CONFLICT ?
		    ": a user bundle may not shadow a system bundle" :
		    ": duplicate sequence");
		if (system) {
			entry_release(&e);
			return (-1);
		}
		nquarantined++;
		syslog(LOG_WARNING, "bundle_registry: quarantined bundle '%s'",
		    capbundle_path(b));
		entry_release(&e);
		return (0);
	}
	bundles[nbundles] = e;
	syslog(LOG_INFO, "bundle_registry: loaded '%s' (%u services)%s%s",
	    capbundle_name(b), capbundle_nservices(b),
	    system ? " [system]" : "", carried_from >= 0 ? " [stale]" : "");
	SWITCHBOARD_PROBE_BUNDLE_LOAD(capbundle_name(b),
	    capbundle_nservices(b), system ? 1 : 0);
	nbundles++;
	return (0);
}

/*
 * Drop the new-array entry at `idx` (compacting the array).  Used to
 * quarantine a user bundle that conflicts with the registry after parsing:
 * a duplicate unit label or provided name, or an unfillable manifest.
 */
static void
registry_drop(unsigned idx, const char *why)
{
	syslog(LOG_WARNING, "bundle_registry: quarantined bundle '%s' (%s)",
	    capbundle_path(bundles[idx].bundle), why);
	nquarantined++;
	entry_release(&bundles[idx]);
	memmove(&bundles[idx], &bundles[idx + 1],
	    (nbundles - idx - 1) * sizeof(*bundles));
	nbundles--;
}

/*
 * Before the indexes are built: every user bundle whose unit labels or
 * provided names collide with an earlier bundle (system bundles come first
 * in the array) or whose manifests do not fill is quarantined, so a user
 * package can never make the scan fail -- or the boot fatal.  Conflicts
 * between two SYSTEM bundles are left for registry_build_indexes to refuse.
 */
static int
registry_prune_user_conflicts(struct svc_manifest *manifest)
{
	unsigned bi, si, bj, sj, pi, pj;

	for (bi = 0; bi < nbundles; bi++) {
		struct capbundle *b = bundles[bi].bundle;
		const char *why = NULL;

		if (bundles[bi].system)
			continue;
		for (si = 0; si < capbundle_nservices(b) && why == NULL; si++) {
			struct capbundle_service *svc = capbundle_service(b, si);
			const char *label = capbundle_svc_label(svc);

			for (bj = 0; bj < bi && why == NULL; bj++) {
				struct capbundle *o = bundles[bj].bundle;

				for (sj = 0; sj < capbundle_nservices(o) &&
				    why == NULL; sj++) {
					struct capbundle_service *os =
					    capbundle_service(o, sj);

					if (strcmp(label,
					    capbundle_svc_label(os)) == 0)
						why = "duplicate unit label";
					for (pi = 0; why == NULL &&
					    pi < capbundle_svc_nprovides(svc); pi++)
						for (pj = 0; why == NULL &&
						    pj < capbundle_svc_nprovides(os); pj++)
							if (strcmp(
							    capbundle_svc_provides(svc, pi),
							    capbundle_svc_provides(os, pj))
							    == 0)
								why = "duplicate provided name";
				}
			}
			if (why == NULL &&
			    capbundle_svc_fill_manifest(svc, manifest) == -1)
				why = "invalid service manifest";
		}
		if (why != NULL) {
			registry_drop(bi, why);
			bi--;
		}
	}
	return (0);
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
	char path[PATH_MAX], canon[PATH_MAX];
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

	/*
	 * Build bundle paths from the canonical root so they compare equal to
	 * what capbundle_open records (realpath) -- a trailing slash or a
	 * symlinked parent must not turn a registered bundle into a new one.
	 */
	if (realpath(dirpath, canon) == NULL)
		strlcpy(canon, dirpath, sizeof(canon));
	dirpath = canon;

	d = opendir(dirpath);
	if (d == NULL)
		return (-1);

	ctx.system = system;
	for (;;) {
		errno = 0;
		de = readdir(d);
		if (de == NULL) {
			if (errno != 0) {
				closedir(d);
				return (-1);
			}
			break;
		}
		if (!is_bundle_name(de->d_name))
			continue;

		if (snprintf(path, sizeof(path), "%s/%s", dirpath,
		    de->d_name) >= (int)sizeof(path)) {
			closedir(d);
			errno = ENAMETOOLONG;
			return (-1);
		}
		if (!trusted_tree(path, errbuf, sizeof(errbuf))) {
			SWITCHBOARD_PROBE_MANIFEST_REJECT(path, errbuf,
			    system ? 1 : 0);
			syslog(LOG_ERR, "bundle_registry: %sbundle '%s' "
			    "untrusted: %s", system ? "SYSTEM " : "", path,
			    errbuf);
			/* Fail the scan or quarantine: see reject_bundle. */
			if (reject_bundle(path, system) == -1) {
				closedir(d);
				return (-1);
			}
			continue;
		}
		if (capbundle_open(path, &b, errbuf, sizeof(errbuf)) == -1) {
			SWITCHBOARD_PROBE_MANIFEST_REJECT(path, errbuf, system ? 1 : 0);
			syslog(LOG_ERR, "bundle_registry: %sbundle '%s' invalid: %s",
			    system ? "SYSTEM " : "", path, errbuf);
			if (reject_bundle(path, system) == -1) {
				closedir(d);
				return (-1);
			}
			continue;
		}

		ret = scan_cb(b, &ctx);
		if (ret != 0) {
			closedir(d);
			return (ret);
		}
	}

	return (closedir(d));
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
		if (state[i].bundle != NULL)
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
	nquarantined = 0;
	struct bundle_state *old_bundles;
	struct provides_entry **old_hash;
	struct svc_manifest *manifest;
	struct stat *sb;
	unsigned i, old_nbundles, old_bundles_cap, nservices;

	/* Failed refreshes must not leave old absence answers authoritative. */

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
	prev_bundles = old_bundles;
	nprev_bundles = old_nbundles;
	memcpy(old_hash, provides_hash, sizeof(provides_hash));
	memset(provides_hash, 0, sizeof(provides_hash));
	nbundles = 0;
	bundles_cap = 0;
	bundles = NULL;

	/* System bundles: optional.  Missing directory is not fatal — the
	 * system may be running without application bundles (e.g., tests,
	 * embedded, or early boot before the filesystem is populated). */
	if (stat(switchboard_bundle_dir_system, sb) == 0 &&
	    S_ISDIR(sb->st_mode)) {
		if (scan_bundle_dir(switchboard_bundle_dir_system, true) == -1) {
			syslog(LOG_ERR,
			    "bundle_registry: system bundle scan failed");
			goto fail;
		}
	} else if (registry_established && old_nbundles > 0 &&
	    old_bundles[0].system) {
		/*
		 * The System root vanished under a running plane (removed,
		 * renamed, revoked).  Treating that as "no System bundles" would
		 * unload every base-system unit; retain the previous registry
		 * and let the watch rescan when the root returns.
		 */
		syslog(LOG_ERR, "bundle_registry: %s disappeared; previous "
		    "registry retained", switchboard_bundle_dir_system);
		goto fail;
	} else {
		syslog(LOG_INFO,
		    "bundle_registry: %s not found, skipping",
		    switchboard_bundle_dir_system);
	}

	/* User bundle directory is optional; malformed bundles are fatal. */
	if (stat(switchboard_bundle_dir_user, sb) == 0 &&
	    S_ISDIR(sb->st_mode)) {
		if (scan_bundle_dir(switchboard_bundle_dir_user, false) == -1) {
			syslog(LOG_ERR,
			    "bundle_registry: user bundle scan failed");
			goto fail;
		}
	} else {
		syslog(LOG_INFO,
		    "bundle_registry: %s not found, skipping",
		    switchboard_bundle_dir_user);
	}

	prev_bundles = NULL;
	nprev_bundles = 0;
	if (nbundles == 0) {
		syslog(LOG_WARNING, "bundle_registry: no bundles loaded");
		registry_established = true;
		registry_dispose(old_bundles, old_nbundles, old_hash);
		free(old_hash);
		free(sb);
		free(manifest);
		return (0);
	}
	(void)registry_prune_user_conflicts(manifest);
	if (registry_build_indexes() == -1)
		goto fail;
	nservices = 0;
	for (i = 0; i < nbundles; i++) {
		nservices += capbundle_nservices(bundles[i].bundle);
		if (nservices > SWITCHBOARD_MAX_SERVICES) {
			if (!bundles[i].system) {
				/* the user bundle that overflows is left out */
				nservices -= capbundle_nservices(bundles[i].bundle);
				registry_drop(i, "service limit reached");
				i--;
				continue;
			}
			syslog(LOG_CRIT,
			    "bundle_registry: %u services exceeds limit %u",
			    nservices, SWITCHBOARD_MAX_SERVICES);
			goto fail;
		}
	}
	for (i = 0; i < nbundles; i++) {
		unsigned si;
		struct capbundle *b = bundles[i].bundle;
		for (si = 0; si < capbundle_nservices(b); si++) {
			struct capbundle_service *svc = capbundle_service(b, si);

			if (capbundle_svc_fill_manifest(svc, manifest) == -1) {
				/* user bundles were pruned above: this is SYSTEM */
				syslog(LOG_CRIT,
				    "bundle_registry: invalid service manifest %s",
				    capbundle_svc_label(svc));
				goto fail;
			}
		}
	}

	syslog(LOG_INFO, "bundle_registry: %u bundles loaded", nbundles);
	SWITCHBOARD_PROBE_BUNDLE_SCAN("all", nbundles);
	registry_established = true;
	registry_dispose(old_bundles, old_nbundles, old_hash);
	free(old_hash);
	free(sb);
	free(manifest);
	return (0);

fail:
	/* Carried entries go back to the previous registry before disposal. */
	for (i = 0; i < nbundles; i++)
		if (bundles[i].carried_from >= 0)
			entry_release(&bundles[i]);
	prev_bundles = NULL;
	nprev_bundles = 0;
	nquarantined = 0;
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
	registry_established = false;
	nquarantined = 0;
}

/* Bundles the last scan quarantined (untrusted or malformed). */
unsigned
bundle_registry_quarantined(void)
{
	return (nquarantined);
}
