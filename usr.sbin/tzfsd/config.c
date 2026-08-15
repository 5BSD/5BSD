/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) configuration: opinionated defaults + optional UCL overlay.
 */

#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void
add_flavor(struct tzfsd_config *cfg, const char *name, enum tzfsd_build build,
    const char *source, bool is_default)
{
	struct tzfsd_flavor_def *f;

	if (cfg->nflavors >= TZFSD_MAX_FLAVORS)
		return;
	f = &cfg->flavors[cfg->nflavors++];
	memset(f, 0, sizeof(*f));
	(void)strlcpy(f->name, name, sizeof(f->name));
	f->build = build;
	if (source != NULL)
		(void)strlcpy(f->source, source, sizeof(f->source));
	f->enabled = true;
	f->is_default = is_default;
	f->available = false;
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
	add_flavor(cfg, "empty", TZFSD_BUILD_LIVE, NULL, false);
	add_flavor(cfg, "native", TZFSD_BUILD_LIVE, NULL, false);
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

static enum tzfsd_build
build_from_string(const char *s, enum tzfsd_build dflt)
{

	if (s == NULL)
		return (dflt);
	if (strcmp(s, "live") == 0)
		return (TZFSD_BUILD_LIVE);
	if (strcmp(s, "baked") == 0)
		return (TZFSD_BUILD_BAKED);
	if (strcmp(s, "source") == 0)
		return (TZFSD_BUILD_SOURCE);
	return (dflt);
}

static void
apply_flavors(struct tzfsd_config *cfg, const ucl_object_t *flavors)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *fo;

	while ((fo = ucl_object_iterate(flavors, &it, true)) != NULL) {
		const char *key = ucl_object_key(fo);
		const ucl_object_t *v;
		struct tzfsd_flavor_def *f;

		if (key == NULL)
			continue;
		f = tzfsd_flavor_find(cfg, key);
		if (f == NULL) {
			/* A config-declared flavor not in the default set. */
			add_flavor(cfg, key, TZFSD_BUILD_SOURCE, NULL, false);
			f = tzfsd_flavor_find(cfg, key);
			if (f == NULL)
				continue;
		}
		if ((v = ucl_object_lookup(fo, "build")) != NULL)
			f->build = build_from_string(ucl_object_tostring(v),
			    f->build);
		if ((v = ucl_object_lookup(fo, "source")) != NULL &&
		    ucl_object_tostring(v) != NULL)
			(void)strlcpy(f->source, ucl_object_tostring(v),
			    sizeof(f->source));
		if ((v = ucl_object_lookup(fo, "enabled")) != NULL)
			f->enabled = ucl_object_toboolean(v);
		if ((v = ucl_object_lookup(fo, "default")) != NULL)
			f->is_default = ucl_object_toboolean(v);
	}
}

/*
 * Overlay a UCL config file on top of the defaults.  A missing file is not an
 * error (defaults stand).  Unknown keys are ignored so the schema can grow.
 */
int
tzfsd_config_load(struct tzfsd_config *cfg, const char *path)
{
	struct ucl_parser *p;
	const ucl_object_t *root, *o, *roots;
	const char *s;
	bool pool_set = false;

	p = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (p == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	if (!ucl_parser_add_file(p, path)) {
		/* No file / unreadable: keep defaults, succeed. */
		ucl_parser_free(p);
		return (0);
	}
	root = ucl_parser_get_object(p);
	if (root == NULL) {
		ucl_parser_free(p);
		return (0);
	}

	if ((o = ucl_object_lookup(root, "pool")) != NULL &&
	    (s = ucl_object_tostring(o)) != NULL) {
		(void)strlcpy(cfg->pool, s, sizeof(cfg->pool));
		pool_set = true;
	}
	/* Recompute the root layout from a possibly-overridden pool. */
	if (pool_set)
		derive_roots(cfg);

	if ((roots = ucl_object_lookup(root, "roots")) != NULL) {
		if ((o = ucl_object_lookup(roots, "base")) != NULL &&
		    (s = ucl_object_tostring(o)) != NULL)
			(void)strlcpy(cfg->base, s, sizeof(cfg->base));
		if ((o = ucl_object_lookup(roots, "persistent")) != NULL &&
		    (s = ucl_object_tostring(o)) != NULL)
			(void)strlcpy(cfg->persistent, s,
			    sizeof(cfg->persistent));
		if ((o = ucl_object_lookup(roots, "ephemeral")) != NULL &&
		    (s = ucl_object_tostring(o)) != NULL)
			(void)strlcpy(cfg->ephemeral, s,
			    sizeof(cfg->ephemeral));
		if ((o = ucl_object_lookup(roots, "templates")) != NULL &&
		    (s = ucl_object_tostring(o)) != NULL)
			(void)strlcpy(cfg->templates, s,
			    sizeof(cfg->templates));
		if ((o = ucl_object_lookup(roots, "mountpoint")) != NULL &&
		    (s = ucl_object_tostring(o)) != NULL)
			(void)strlcpy(cfg->mountpoint, s,
			    sizeof(cfg->mountpoint));
	}

	if ((o = ucl_object_lookup(root, "ephemeral")) != NULL) {
		const ucl_object_t *sy = ucl_object_lookup(o, "sync");
		if (sy != NULL && (s = ucl_object_tostring(sy)) != NULL)
			(void)strlcpy(cfg->ephemeral_sync, s,
			    sizeof(cfg->ephemeral_sync));
	}

	if ((o = ucl_object_lookup(root, "flavors")) != NULL)
		apply_flavors(cfg, o);

	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(p);
	return (0);
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
		return (0);
	for (i = 0; i < n; i++) {
		const char *nm = names[i]->d_name;
		size_t len = strlen(nm);

		if (len > 4 && strcmp(nm + len - 4, ".ucl") == 0) {
			char path[TZFSD_MAXPATH];

			(void)snprintf(path, sizeof(path), "%s/%s", dir, nm);
			(void)tzfsd_config_load(cfg, path);
		}
		free(names[i]);
	}
	free(names);
	return (0);
}
