/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) configuration: opinionated defaults + optional UCL overlay.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
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
	(void)snprintf(cfg->templates, sizeof(cfg->templates),
	    "%s/.templates", cfg->base);
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

static int
add_flavor(struct tzfsd_config *cfg, const char *name, enum tzfsd_build build,
    const char *source, bool is_default)
{
	struct tzfsd_flavor_def *f;

	if (!identifier_valid(name, TZFSD_FLAVOR_MAX) ||
	    cfg->nflavors >= TZFSD_MAX_FLAVORS) {
		errno = cfg->nflavors >= TZFSD_MAX_FLAVORS ? ENOSPC : EINVAL;
		return (-1);
	}
	if (source != NULL && strnlen(source, TZFSD_MAXPATH) == TZFSD_MAXPATH) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	f = &cfg->flavors[cfg->nflavors++];
	memset(f, 0, sizeof(*f));
	(void)strlcpy(f->name, name, sizeof(f->name));
	f->build = build;
	if (source != NULL)
		(void)strlcpy(f->source, source, sizeof(f->source));
	f->enabled = true;
	f->is_default = is_default;
	f->available = false;
	return (0);
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

	/*
	 * The built-in flavor set is deliberately just the two that need no
	 * external content, so the broker stays self-contained: empty is a
	 * fresh dataset and native is a copy-on-write clone of the running boot
	 * environment (it ships for free, not as a baked second copy).
	 *
	 * OS-image flavors (e.g. freebsd, linux) are *not* built in -- curating
	 * and shipping a distro rootfs is a separate concern from brokering
	 * storage.  They are contributed as data by a flavor-catalog package
	 * that drops a config fragment under the conf.d directory (declaring the
	 * flavor and its baked artifact) plus the artifact itself; tzfsd then
	 * offers whatever templates it finds.  See tzfsd_config_load_confd().
	 */
	(void)add_flavor(cfg, "empty", TZFSD_BUILD_LIVE, NULL, false);
	(void)add_flavor(cfg, "native", TZFSD_BUILD_LIVE, NULL, false);
}

struct tzfsd_flavor_def *
tzfsd_flavor_find(struct tzfsd_config *cfg, const char *name)
{
	unsigned i;

	for (i = 0; i < cfg->nflavors; i++)
		if (strcmp(cfg->flavors[i].name, name) == 0)
			return (&cfg->flavors[i]);
	return (NULL);
}

static int
build_from_string(const char *s, enum tzfsd_build *build)
{

	if (s == NULL || build == NULL)
		return (errno = EINVAL, -1);
	if (strcmp(s, "live") == 0)
		*build = TZFSD_BUILD_LIVE;
	else if (strcmp(s, "baked") == 0)
		*build = TZFSD_BUILD_BAKED;
	else if (strcmp(s, "source") == 0)
		*build = TZFSD_BUILD_SOURCE;
	else
		return (errno = EINVAL, -1);
	return (0);
}

static int
apply_flavors(struct tzfsd_config *cfg, const ucl_object_t *flavors)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *fo;

	if (ucl_object_type(flavors) != UCL_OBJECT)
		return (errno = EINVAL, -1);
	while ((fo = ucl_object_iterate(flavors, &it, true)) != NULL) {
		const char *key = ucl_object_key(fo);
		const ucl_object_t *v;
		struct tzfsd_flavor_def *f;

		if (key == NULL || !identifier_valid(key, TZFSD_FLAVOR_MAX) ||
		    ucl_object_type(fo) != UCL_OBJECT)
			return (errno = EINVAL, -1);
		f = tzfsd_flavor_find(cfg, key);
		if (f == NULL) {
			/* A config-declared flavor not in the default set. */
			if (add_flavor(cfg, key, TZFSD_BUILD_SOURCE, NULL,
			    false) == -1)
				return (-1);
			f = tzfsd_flavor_find(cfg, key);
			if (f == NULL)
				return (errno = EINVAL, -1);
		}
		if ((v = ucl_object_lookup(fo, "build")) != NULL &&
		    (ucl_object_type(v) != UCL_STRING ||
		    build_from_string(ucl_object_tostring(v), &f->build) == -1))
			return (errno = EINVAL, -1);
		if ((v = ucl_object_lookup(fo, "source")) != NULL) {
			if (ucl_object_type(v) != UCL_STRING ||
			    ucl_object_tostring(v) == NULL ||
			    strlcpy(f->source, ucl_object_tostring(v),
			    sizeof(f->source)) >= sizeof(f->source))
				return (errno = EINVAL, -1);
		}
		if ((v = ucl_object_lookup(fo, "enabled")) != NULL) {
			if (ucl_object_type(v) != UCL_BOOLEAN)
				return (errno = EINVAL, -1);
			f->enabled = ucl_object_toboolean(v);
		}
		if ((v = ucl_object_lookup(fo, "default")) != NULL) {
			if (ucl_object_type(v) != UCL_BOOLEAN)
				return (errno = EINVAL, -1);
			f->is_default = ucl_object_toboolean(v);
		}
	}
	return (0);
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
	const struct tzfsd_flavor_def *flavor;
	unsigned defaults, i;

	if (!identifier_valid(cfg->pool, sizeof(cfg->pool)) ||
	    !dataset_under_pool(cfg->pool, cfg->base) ||
	    !dataset_under_pool(cfg->pool, cfg->persistent) ||
	    !dataset_under_pool(cfg->pool, cfg->ephemeral) ||
	    !dataset_under_pool(cfg->pool, cfg->templates) ||
	    !absolute_path_valid(cfg->mountpoint) ||
	    (strcmp(cfg->ephemeral_sync, "disabled") != 0 &&
	    strcmp(cfg->ephemeral_sync, "standard") != 0 &&
	    strcmp(cfg->ephemeral_sync, "always") != 0))
		return (errno = EINVAL, -1);
	defaults = 0;
	for (i = 0; i < cfg->nflavors; i++) {
		flavor = &cfg->flavors[i];
		if (!identifier_valid(flavor->name, sizeof(flavor->name)) ||
		    (flavor->is_default && !flavor->enabled) ||
		    (flavor->build == TZFSD_BUILD_BAKED &&
		    !absolute_path_valid(flavor->source)) ||
		    (flavor->build == TZFSD_BUILD_LIVE &&
		    strcmp(flavor->name, "empty") != 0 &&
		    strcmp(flavor->name, "native") != 0))
			return (errno = EINVAL, -1);
		if (flavor->is_default)
			defaults++;
	}
	if (defaults > 1)
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
		if ((o = ucl_object_lookup(roots, "templates")) != NULL &&
		    copy_string(cfg->templates, sizeof(cfg->templates), o) == -1)
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

	if ((o = ucl_object_lookup(root, "flavors")) != NULL &&
	    apply_flavors(cfg, o) == -1)
		goto invalid;
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
 * Overlay every *.ucl fragment in a conf.d directory, in lexical order, on top
 * of the already-loaded configuration.  This is the seam that keeps OS-image
 * curation out of the broker: a separately-packaged flavor catalog contributes
 * its flavors (freebsd, linux, ...) by dropping a fragment here plus the baked
 * artifact it points at, and tzfsd offers whatever it finds.  A missing or
 * unreadable directory is not an error -- the built-in defaults stand.
 */
int
tzfsd_config_load_confd(struct tzfsd_config *cfg, const char *dir)
{
	struct dirent **names;
	int n, i;

	n = scandir(dir, &names, NULL, alphasort);
	if (n < 0)
		return (errno == ENOENT ? 0 : -1);
	for (i = 0; i < n; i++) {
		const char *nm = names[i]->d_name;
		size_t len = strlen(nm);

		if (len > 4 && strcmp(nm + len - 4, ".ucl") == 0) {
			char path[TZFSD_MAXPATH];

			(void)snprintf(path, sizeof(path), "%s/%s", dir, nm);
			if (tzfsd_config_load(cfg, path) == -1) {
				int error = errno;

				while (i < n)
					free(names[i++]);
				free(names);
				errno = error;
				return (-1);
			}
		}
		free(names[i]);
	}
	free(names);
	return (0);
}
