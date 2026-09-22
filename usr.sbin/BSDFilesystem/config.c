/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdfilesystem(8) configuration: opinionated defaults + optional UCL overlay.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "bsdfilesystem.h"

/*
 * Derive the /Capabilities dataset layout from a pool name.  Only fields the
 * caller has not explicitly set are recomputed; callers pass a freshly
 * defaulted config so every field is (re)derived here.
 */
static void
derive_roots(struct bsdfilesystem_config *cfg)
{

	(void)snprintf(cfg->base, sizeof(cfg->base), "%s/Capabilities",
	    cfg->pool);
	/*
	 * The durable-container root: each capability unit's persistent data lives
	 * at Data/<bundle>/<unit>/persistent under it, so the per-bundle container
	 * is the ownership record the reconcile reaps by (docs/capability-
	 * container-model.md).
	 */
	(void)snprintf(cfg->persistent, sizeof(cfg->persistent),
	    "%s/Data", cfg->base);
	(void)snprintf(cfg->ephemeral, sizeof(cfg->ephemeral),
	    "%s/ephemeral", cfg->base);
}

static bool
identifier_valid(const char *name, size_t capacity)
{
	size_t i, length;

	length = strnlen(name, capacity);
	if (length == 0 || length == capacity || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (false);
	for (i = 0; i < length; i++) {
		if (!((name[i] >= 'a' && name[i] <= 'z') ||
		    (name[i] >= 'A' && name[i] <= 'Z') ||
		    (name[i] >= '0' && name[i] <= '9') || name[i] == '.' ||
		    name[i] == '_' || name[i] == '-' || name[i] == ':'))
			return (false);
	}
	return (true);
}

void
bsdfilesystem_config_defaults(struct bsdfilesystem_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	(void)strlcpy(cfg->pool, "zroot", sizeof(cfg->pool));
	derive_roots(cfg);
	(void)strlcpy(cfg->mountpoint, "/Capabilities",
	    sizeof(cfg->mountpoint));
	(void)strlcpy(cfg->ephemeral_sync, "disabled",
	    sizeof(cfg->ephemeral_sync));
	cfg->default_refquota = BSDFILESYSTEM_DEFAULT_REFQUOTA;
	cfg->reclaim_interval = BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT;
	cfg->staging_idle_grace = BSDFILESYSTEM_STAGING_IDLE_GRACE;
}

static int
copy_string(char *destination, size_t capacity, const ucl_object_t *object)
{
	const char *value;

	if (object == NULL || ucl_object_type(object) != UCL_STRING ||
	    (value = ucl_object_tostring(object)) == NULL || value[0] == '\0' ||
	    strlcpy(destination, value, capacity) >= capacity)
		return (errno = EINVAL, -1);
	return (0);
}

static bool
dataset_under_pool(const char *pool, const char *dataset)
{
	const char *component, *slash;
	size_t length, component_length;

	length = strlen(pool);
	if (strncmp(pool, dataset, length) != 0 || dataset[length] != '/' ||
	    dataset[length + 1] == '\0')
		return (false);
	component = dataset + length + 1;
	for (;;) {
		slash = strchr(component, '/');
		component_length = slash == NULL ? strlen(component) :
		    (size_t)(slash - component);
		if (component_length == 0 ||
		    (component_length == 1 && component[0] == '.') ||
		    (component_length == 2 && component[0] == '.' &&
		    component[1] == '.') ||
		    memchr(component, '@', component_length) != NULL ||
		    memchr(component, '#', component_length) != NULL)
			return (false);
		if (slash == NULL)
			return (true);
		component = slash + 1;
	}
}

static bool
absolute_path_valid(const char *path)
{
	const char *component, *slash;
	size_t component_length;

	if (path[0] != '/' || path[1] == '\0')
		return (false);
	component = path + 1;
	for (;;) {
		slash = strchr(component, '/');
		component_length = slash == NULL ? strlen(component) :
		    (size_t)(slash - component);
		if (component_length == 0 ||
		    (component_length == 1 && component[0] == '.') ||
		    (component_length == 2 && component[0] == '.' &&
		    component[1] == '.'))
			return (false);
		if (slash == NULL)
			return (true);
		component = slash + 1;
	}
}

static int
config_validate(const struct bsdfilesystem_config *cfg)
{

	if (!identifier_valid(cfg->pool, sizeof(cfg->pool)) ||
	    !dataset_under_pool(cfg->pool, cfg->base) ||
	    !dataset_under_pool(cfg->pool, cfg->persistent) ||
	    !dataset_under_pool(cfg->pool, cfg->ephemeral) ||
	    !absolute_path_valid(cfg->mountpoint) ||
	    (strcmp(cfg->ephemeral_sync, "disabled") != 0 &&
	    strcmp(cfg->ephemeral_sync, "standard") != 0 &&
	    strcmp(cfg->ephemeral_sync, "always") != 0))
		return (errno = EINVAL, -1);
	return (0);
}

/*
 * Overlay a UCL config file on top of the defaults.  A missing file is not an
 * error (defaults stand).  Unknown keys are ignored so the schema can grow.
 */
/*
 * Parse a UCL config from an already-open, already-vetted descriptor and overlay
 * it on the defaults.  Does NOT close fd (caller owns it).  Restores the prior
 * config on any parse error.
 */
static int
config_parse_fd(struct bsdfilesystem_config *cfg, int fd)
{
	struct bsdfilesystem_config saved;
	struct ucl_parser *p;
	const ucl_object_t *root, *o, *roots;
	int error;
	bool pool_set = false;

	saved = *cfg;
	p = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (p == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	if (!ucl_parser_add_fd(p, fd)) {
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}
	root = ucl_parser_get_object(p);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		if (root != NULL)
			ucl_object_unref(__DECONST(ucl_object_t *, root));
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}

	if ((o = ucl_object_lookup(root, "pool")) != NULL) {
		if (copy_string(cfg->pool, sizeof(cfg->pool), o) == -1)
			goto invalid;
		pool_set = true;
	}
	/* Recompute the root layout from a possibly-overridden pool. */
	if (pool_set)
		derive_roots(cfg);

	if ((roots = ucl_object_lookup(root, "roots")) != NULL) {
		if (ucl_object_type(roots) != UCL_OBJECT)
			goto invalid;
		if ((o = ucl_object_lookup(roots, "base")) != NULL &&
		    copy_string(cfg->base, sizeof(cfg->base), o) == -1)
			goto invalid;
		if ((o = ucl_object_lookup(roots, "persistent")) != NULL &&
		    copy_string(cfg->persistent, sizeof(cfg->persistent), o) == -1)
			goto invalid;
		if ((o = ucl_object_lookup(roots, "ephemeral")) != NULL &&
		    copy_string(cfg->ephemeral, sizeof(cfg->ephemeral), o) == -1)
			goto invalid;
		if ((o = ucl_object_lookup(roots, "mountpoint")) != NULL &&
		    copy_string(cfg->mountpoint, sizeof(cfg->mountpoint), o) == -1)
			goto invalid;
	}

	if ((o = ucl_object_lookup(root, "ephemeral")) != NULL) {
		const ucl_object_t *sy = ucl_object_lookup(o, "sync");

		if (ucl_object_type(o) != UCL_OBJECT ||
		    (sy != NULL && copy_string(cfg->ephemeral_sync,
		    sizeof(cfg->ephemeral_sync), sy) == -1))
			goto invalid;
	}

	/*
	 * Default per-claim space ceiling, in bytes (UCL size suffixes like "1gb"
	 * are accepted and pre-multiplied by the parser).  0 disables the ceiling.
	 */
	if ((o = ucl_object_lookup(root, "default_refquota")) != NULL) {
		int64_t v;

		if (ucl_object_type(o) != UCL_INT ||
		    (v = ucl_object_toint(o)) < 0)
			goto invalid;
		cfg->default_refquota = (uint64_t)v;
	}

	/*
	 * Container reconcile cadence in seconds (== the grace window).  Bounded;
	 * out-of-range values are a config error, not silently clamped.
	 */
	if ((o = ucl_object_lookup(root, "reclaim_interval")) != NULL) {
		double v;

		/* "300", "5min", "1h": UCL parses time suffixes to seconds. */
		if (ucl_object_type(o) != UCL_INT &&
		    ucl_object_type(o) != UCL_TIME)
			goto invalid;
		v = ucl_object_todouble(o);
		if (v < BSDFILESYSTEM_RECLAIM_INTERVAL_MIN ||
		    v > BSDFILESYSTEM_RECLAIM_INTERVAL_MAX) {
			/*
			 * A cadence outside the bounds is a mistake, not a reason
			 * to take the storage plane down: keep the default and say
			 * so.
			 */
			syslog(LOG_WARNING, "config: reclaim_interval %g outside "
			    "%u..%u, keeping %u", v, BSDFILESYSTEM_RECLAIM_INTERVAL_MIN,
			    BSDFILESYSTEM_RECLAIM_INTERVAL_MAX,
			    BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT);
			cfg->reclaim_interval = BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT;
		} else
			cfg->reclaim_interval = (unsigned)v;
	}

	/*
	 * Minimum age of an abandoned TXN staging clone before the live-system
	 * idle reap reclaims it (a live txn is protected by its mount regardless).
	 * Bounded; out-of-range keeps the default.
	 */
	if ((o = ucl_object_lookup(root, "staging_idle_grace")) != NULL) {
		double v;

		if (ucl_object_type(o) != UCL_INT &&
		    ucl_object_type(o) != UCL_TIME)
			goto invalid;
		v = ucl_object_todouble(o);
		if (v < BSDFILESYSTEM_STAGING_IDLE_GRACE_MIN ||
		    v > BSDFILESYSTEM_STAGING_IDLE_GRACE_MAX) {
			syslog(LOG_WARNING, "config: staging_idle_grace %g outside "
			    "%u..%u, keeping %u", v,
			    BSDFILESYSTEM_STAGING_IDLE_GRACE_MIN,
			    BSDFILESYSTEM_STAGING_IDLE_GRACE_MAX,
			    BSDFILESYSTEM_STAGING_IDLE_GRACE);
			cfg->staging_idle_grace = BSDFILESYSTEM_STAGING_IDLE_GRACE;
		} else
			cfg->staging_idle_grace = (unsigned)v;
	}

	/*
	 * Per-label isolated-open policy (default-deny).  Each entry grants one
	 * exact absolute path to one label with a set of rights.  This is the
	 * operator policy for BSDFILESYSTEM_OP_OPEN; absent = no path is openable.
	 */
	if ((o = ucl_object_lookup(root, "open_paths")) != NULL) {
		const ucl_object_t *ent;
		ucl_object_iter_t it = NULL;

		if (ucl_object_type(o) != UCL_ARRAY)
			goto invalid;
		cfg->nopen_policy = 0;
		while ((ent = ucl_object_iterate(o, &it, true)) != NULL) {
			struct bsdfilesystem_open_policy *pol;
			const ucl_object_t *lb, *pa, *ri, *rv;
			ucl_object_iter_t rit = NULL;

			if (cfg->nopen_policy >= BSDFILESYSTEM_MAX_OPEN_POLICY ||
			    ucl_object_type(ent) != UCL_OBJECT)
				goto invalid;
			pol = &cfg->open_policy[cfg->nopen_policy];
			memset(pol, 0, sizeof(*pol));
			lb = ucl_object_lookup(ent, "label");
			pa = ucl_object_lookup(ent, "path");
			ri = ucl_object_lookup(ent, "rights");
			if (lb == NULL || pa == NULL || ri == NULL ||
			    copy_string(pol->label, sizeof(pol->label), lb) == -1 ||
			    copy_string(pol->path, sizeof(pol->path), pa) == -1 ||
			    ucl_object_type(ri) != UCL_ARRAY)
				goto invalid;
			/* Absolute, no empty or ".." traversal component. */
			if (!absolute_path_valid(pol->path))
				goto invalid;
			{
				const ucl_object_t *px = ucl_object_lookup(ent,
				    "prefix");

				pol->prefix = px != NULL &&
				    ucl_object_toboolean(px);
			}
			while ((rv = ucl_object_iterate(ri, &rit, true)) != NULL) {
				const char *s = ucl_object_tostring(rv);

				if (s == NULL)
					goto invalid;
				if (strcmp(s, "read") == 0)
					pol->rights |= BSDFILESYSTEM_OPEN_READ;
				else if (strcmp(s, "write") == 0)
					pol->rights |= BSDFILESYSTEM_OPEN_WRITE;
				else if (strcmp(s, "exec") == 0)
					pol->rights |= BSDFILESYSTEM_OPEN_EXEC;
				else if (strcmp(s, "lookup") == 0)
					pol->rights |= BSDFILESYSTEM_OPEN_LOOKUP;
				else if (strcmp(s, "ioctl") == 0)
					pol->rights |= BSDFILESYSTEM_OPEN_IOCTL;
				else
					goto invalid;
			}
			if (pol->rights == 0)
				goto invalid;
			cfg->nopen_policy++;
		}
	}

	if (config_validate(cfg) == -1)
		goto invalid;

	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(p);
	return (0);

invalid:
	error = errno != 0 ? errno : EINVAL;
	*cfg = saved;
	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(p);
	errno = error;
	return (-1);
}

/*
 * Overlay a UCL config file on the defaults (legacy / -c / tests): hardened open
 * plus the trusted-owner, not-group/other-writable ownership check.  A missing
 * file is not an error (defaults stand).
 */
int
bsdfilesystem_config_load(struct bsdfilesystem_config *cfg, const char *path)
{
	struct stat sb;
	int error, fd, rc;

	if (cfg == NULL || path == NULL)
		return (errno = EINVAL, -1);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (errno == ENOENT ? 0 : -1);
	if (fstat(fd, &sb) == -1) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
	if (!S_ISREG(sb.st_mode) || sb.st_size > 1024 * 1024 ||
	    sb.st_uid != geteuid() || (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		close(fd);
		return (errno = EPERM, -1);
	}
	rc = config_parse_fd(cfg, fd);
	error = errno;
	close(fd);
	errno = error;
	return (rc);
}

/*
 * Load the config from a descriptor the born-in-capmode broker opened itself via
 * the switchboard-delivered "/" (openat(root_fd, "Capabilities/Config/...")).
 * Possession of the descriptor is the authorization -- no st_uid ownership check
 * (the broker is not the config's owner and cannot open it by path in capmode) --
 * only a regular-file + size sanity guard.  Takes ownership of fd and closes it;
 * fd < 0 leaves the defaults untouched.
 */
int
bsdfilesystem_config_load_fd(struct bsdfilesystem_config *cfg, int fd)
{
	struct stat sb;
	int error, rc;

	if (cfg == NULL) {
		if (fd >= 0)
			(void)close(fd);
		return (errno = EINVAL, -1);
	}
	if (fd < 0)
		return (0);
	if (fstat(fd, &sb) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	if (!S_ISREG(sb.st_mode) || sb.st_size > 1024 * 1024) {
		(void)close(fd);
		return (errno = EPERM, -1);
	}
	rc = config_parse_fd(cfg, fd);
	error = errno;
	(void)close(fd);
	errno = error;
	return (rc);
}
