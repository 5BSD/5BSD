/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libcapbundle — parse and validate 5BSD .cap bundles.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "libcapbundle_internal.h"

static int
manifest_copy(const char *src, char *dst, size_t dstsz)
{

	return (strlcpy(dst, src, dstsz) < dstsz ? 0 : -1);
}

/* --- Public API --- */

int
capbundle_open(const char *path, struct capbundle **bp,
    char *errbuf, size_t errlen)
{
	struct capbundle *b;
	struct stat sb;
	DIR *d;
	struct dirent *de;
	char services_dir[PATH_MAX];
	char svc_path[PATH_MAX];
	char *slash;
	size_t len;

	if (stat(path, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
		if (errbuf)
			snprintf(errbuf, errlen, "%s: not a directory", path);
		return (-1);
	}

	b = calloc(1, sizeof(*b));
	if (b == NULL) {
		if (errbuf)
			snprintf(errbuf, errlen, "out of memory");
		return (-1);
	}

	/* Store path and derive name. */
	if (realpath(path, b->path) == NULL)
		strlcpy(b->path, path, sizeof(b->path));

	/* Strip trailing slash for basename. */
	strlcpy(b->name, b->path, sizeof(b->name));
	len = strlen(b->name);
	if (len > 0 && b->name[len - 1] == '/')
		b->name[len - 1] = '\0';
	slash = strrchr(b->name, '/');
	if (slash != NULL)
		memmove(b->name, slash + 1, strlen(slash + 1) + 1);

	/* Check etc/ directory for service manifests. */
	snprintf(services_dir, sizeof(services_dir),
	    "%s/etc", b->path);
	d = opendir(services_dir);
	if (d == NULL) {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: etc/ not found", b->name);
		free(b);
		return (-1);
	}

	/* Parse each .ucl in Services/. */
	{
		unsigned nfailed = 0;
		char fail_errbuf[256];

		while ((de = readdir(d)) != NULL) {
			len = strlen(de->d_name);
			if (len < 5 ||
			    strcmp(de->d_name + len - 4, ".ucl") != 0)
				continue;
			if (b->nservices >= CAPBUNDLE_MAX_SERVICES)
				break;

			snprintf(svc_path, sizeof(svc_path), "%s/%s",
			    services_dir, de->d_name);

			if (capbundle_parse_service_ucl(svc_path, b->path,
			    &b->services[b->nservices],
			    b->bundle_id, sizeof(b->bundle_id),
			    b->version, sizeof(b->version),
			    b->author, sizeof(b->author),
			    fail_errbuf,
			    sizeof(fail_errbuf)) == 0) {
				b->nservices++;
			} else {
				syslog(LOG_WARNING,
				    "capbundle %s: skipping %s: %s",
				    b->name, de->d_name, fail_errbuf);
				nfailed++;
			}
		}
		closedir(d);

		/* Fail the bundle if any Service.ucl files failed to parse. */
		if (nfailed > 0) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: %u service(s) failed to parse",
				    b->name, nfailed);
			capbundle_close(b);
			return (-1);
		}
	}

	if (b->nservices == 0) {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: no valid services found", b->name);
		free(b);
		return (-1);
	}

	*bp = b;
	return (0);
}

void
capbundle_close(struct capbundle *b)
{

	free(b);
}

const char *
capbundle_id(const struct capbundle *b)
{

	return (b->bundle_id);
}

const char *
capbundle_version(const struct capbundle *b)
{

	return (b->version);
}

const char *
capbundle_author(const struct capbundle *b)
{

	return (b->author);
}

const char *
capbundle_path(const struct capbundle *b)
{

	return (b->path);
}

const char *
capbundle_name(const struct capbundle *b)
{

	return (b->name);
}

unsigned
capbundle_nservices(const struct capbundle *b)
{

	return (b->nservices);
}

struct capbundle_service *
capbundle_service(const struct capbundle *b, unsigned idx)
{

	if (idx >= b->nservices)
		return (NULL);
	/* Safe: callers receive const pointer via the public API. */
	return (__DECONST(struct capbundle_service *, &b->services[idx]));
}

const char *
capbundle_svc_program(const struct capbundle_service *s)
{

	return (s->program);
}

const char *
capbundle_svc_label(const struct capbundle_service *s)
{

	return (s->label);
}

unsigned
capbundle_svc_nprovides(const struct capbundle_service *s)
{

	return (s->nprovides);
}

const char *
capbundle_svc_provides(const struct capbundle_service *s, unsigned idx)
{

	if (idx >= s->nprovides)
		return (NULL);
	return (s->provides[idx]);
}

unsigned
capbundle_svc_nrequires(const struct capbundle_service *s)
{

	return (s->nrequires);
}

const char *
capbundle_svc_requires(const struct capbundle_service *s, unsigned idx)
{

	if (idx >= s->nrequires)
		return (NULL);
	return (s->requires[idx]);
}

bool
capbundle_svc_on_demand(const struct capbundle_service *s)
{

	return (s->on_demand);
}

/*
 * Fill a svc_manifest from a bundle service.
 * This is the canonical way to populate all fields including capabilities.
 */
int
capbundle_svc_fill_manifest(const struct capbundle_service *s,
    struct svc_manifest *m)
{
	unsigned i;

	memset(m, 0, sizeof(*m));

	if (manifest_copy(s->label, m->label, sizeof(m->label)) == -1 ||
	    manifest_copy(s->program, m->program, sizeof(m->program)) == -1 ||
	    manifest_copy(s->user, m->user, sizeof(m->user)) == -1 ||
	    manifest_copy(s->group, m->group, sizeof(m->group)) == -1)
		return (-1);

	m->nprovides = s->nprovides;
	for (i = 0; i < s->nprovides && i < CAPBUNDLE_MAX_PROVIDES; i++) {
		if (manifest_copy(s->provides[i], m->provides[i],
		    sizeof(m->provides[i])) == -1)
			return (-1);
	}

	m->nrequires = s->nrequires;
	for (i = 0; i < s->nrequires && i < CAPBUNDLE_MAX_REQUIRES; i++) {
		if (manifest_copy(s->requires[i], m->requires[i],
		    sizeof(m->requires[i])) == -1)
			return (-1);
	}

	m->cap_system = s->cap_system;
	m->on_demand = s->on_demand;
	m->restart = s->restart;
	m->stop_timeout = s->stop_timeout > 0 ? s->stop_timeout : 5;
	m->max_failures = s->max_failures > 0 ? s->max_failures : 10;

	/* Path capabilities */
	m->ncap_paths = s->ncap_paths;
	for (i = 0; i < s->ncap_paths; i++) {
		if (manifest_copy(s->cap_paths[i], m->cap_paths[i],
		    sizeof(m->cap_paths[i])) == -1)
			return (-1);
	}

	/* File capabilities */
	m->ncap_files = s->ncap_files;
	for (i = 0; i < s->ncap_files; i++) {
		if (manifest_copy(s->cap_files[i].path,
		    m->cap_files[i].path,
		    sizeof(m->cap_files[i].path)) == -1)
			return (-1);
		m->cap_files[i].actions = s->cap_files[i].actions;
	}

	/* Network capabilities */
	m->ncap_net = s->ncap_net;
	for (i = 0; i < s->ncap_net; i++)
		m->cap_net[i] = s->cap_net[i];

	/* Jail capabilities */
	m->ncap_jail = s->ncap_jail;
	for (i = 0; i < s->ncap_jail; i++)
		m->cap_jail[i] = s->cap_jail[i];

	/* Kernel module requirements */
	m->nkmod_requires = s->nkmod_requires;
	for (i = 0; i < s->nkmod_requires; i++)
		strlcpy(m->kmod_requires[i], s->kmod_requires[i],
		    sizeof(m->kmod_requires[i]));

	return (0);
}

/* --- Directory Scanning --- */

static bool
bundle_name_has_suffix(const char *name)
{
	size_t len;

	len = strlen(name);
	if (len < 4)
		return (false);
	return (strcmp(name + len - 4, ".cap") == 0);
}

int
capbundle_scan_dir(const char *dirpath, capbundle_scan_cb cb, void *ctx)
{
	DIR *d;
	struct dirent *de;
	char path[PATH_MAX];
	struct capbundle *b;
	char errbuf[256];
	int ret;

	d = opendir(dirpath);
	if (d == NULL)
		return (-1);

	while ((de = readdir(d)) != NULL) {
		if (!bundle_name_has_suffix(de->d_name))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);

		if (capbundle_open(path, &b, errbuf, sizeof(errbuf)) == -1)
			continue;	/* skip invalid bundles */

		ret = cb(b, ctx);
		if (ret != 0) {
			closedir(d);
			return (ret);
		}
		/* Callback is responsible for closing b. */
	}

	closedir(d);
	return (0);
}
