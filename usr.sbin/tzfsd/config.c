/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) configuration: opinionated defaults + optional UCL overlay.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "tzfsd.h"

/*
 * Derive the /Capabilities dataset layout from a pool name.  Only fields the
 * caller has not explicitly set are recomputed; callers pass a freshly
 * defaulted config so every field is (re)derived here.
 */
static void
derive_roots(struct tzfsd_config *cfg)
{

	(void)snprintf(cfg->base, sizeof(cfg->base), "%s/Capabilities",
	    cfg->pool);
	(void)snprintf(cfg->persistent, sizeof(cfg->persistent),
	    "%s/persistent", cfg->base);
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
		    name[i] == '_' || name[i] == '-'))
			return (false);
	}
	return (true);
}

void
tzfsd_config_defaults(struct tzfsd_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	(void)strlcpy(cfg->pool, "zroot", sizeof(cfg->pool));
	derive_roots(cfg);
	(void)strlcpy(cfg->mountpoint, "/Capabilities",
	    sizeof(cfg->mountpoint));
	(void)strlcpy(cfg->ephemeral_sync, "disabled",
	    sizeof(cfg->ephemeral_sync));
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
config_validate(const struct tzfsd_config *cfg)
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
int
tzfsd_config_load(struct tzfsd_config *cfg, const char *path)
{
	struct tzfsd_config saved;
	struct ucl_parser *p;
	const ucl_object_t *root, *o, *roots;
	struct stat sb;
	int error, fd;
	bool pool_set = false;

	if (cfg == NULL || path == NULL)
		return (errno = EINVAL, -1);
	saved = *cfg;
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
	p = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (p == NULL) {
		close(fd);
		errno = ENOMEM;
		return (-1);
	}
	if (!ucl_parser_add_fd(p, fd)) {
		close(fd);
		ucl_parser_free(p);
		return (errno = EINVAL, -1);
	}
	close(fd);
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
	 * Per-label isolated-open policy (default-deny).  Each entry grants one
	 * exact absolute path to one label with a set of rights.  This is the
	 * operator policy for TZFSD_OP_OPEN; absent = no path is openable.
	 */
	if ((o = ucl_object_lookup(root, "open_paths")) != NULL) {
		const ucl_object_t *ent;
		ucl_object_iter_t it = NULL;

		if (ucl_object_type(o) != UCL_ARRAY)
			goto invalid;
		cfg->nopen_policy = 0;
		while ((ent = ucl_object_iterate(o, &it, true)) != NULL) {
			struct tzfsd_open_policy *pol;
			const ucl_object_t *lb, *pa, *ri, *rv;
			ucl_object_iter_t rit = NULL;

			if (cfg->nopen_policy >= TZFSD_MAX_OPEN_POLICY ||
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
			/* Absolute, no traversal component. */
			if (pol->path[0] != '/' || strstr(pol->path, "..") != NULL)
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
					pol->rights |= TZFSD_OPEN_READ;
				else if (strcmp(s, "write") == 0)
					pol->rights |= TZFSD_OPEN_WRITE;
				else if (strcmp(s, "exec") == 0)
					pol->rights |= TZFSD_OPEN_EXEC;
				else if (strcmp(s, "lookup") == 0)
					pol->rights |= TZFSD_OPEN_LOOKUP;
				else if (strcmp(s, "ioctl") == 0)
					pol->rights |= TZFSD_OPEN_IOCTL;
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
