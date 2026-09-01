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
	char units_dir[PATH_MAX];
	char unit_dir[PATH_MAX];
	char manifest_path[PATH_MAX];
	char *slash;
	size_t len;

	if (bp != NULL)
		*bp = NULL;
	if (errbuf != NULL && errlen > 0)
		errbuf[0] = '\0';
	if (path == NULL || bp == NULL) {
		errno = EINVAL;
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "path and result are required");
		return (-1);
	}

	if (lstat(path, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
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

	if (snprintf(manifest_path, sizeof(manifest_path), "%s/Bundle.ucl",
	    b->path) >= (int)sizeof(manifest_path) ||
	    capbundle_parse_bundle_ucl(manifest_path, b, errbuf, errlen) == -1) {
		capbundle_close(b);
		return (-1);
	}
	/* The root is intentionally small and closed to legacy layouts. */
	d = opendir(b->path);
	if (d == NULL) {
		capbundle_close(b);
		return (-1);
	}
	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 ||
		    strcmp(de->d_name, "Bundle.ucl") == 0 ||
		    strcmp(de->d_name, "Units") == 0 ||
		    strcmp(de->d_name, "Shared") == 0)
			continue;
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: root entry is not allowed: %s",
			    b->name, de->d_name);
		closedir(d);
		capbundle_close(b);
		return (-1);
	}
	closedir(d);
	if (snprintf(units_dir, sizeof(units_dir), "%s/Units", b->path) >=
	    (int)sizeof(units_dir) || lstat(units_dir, &sb) == -1 ||
	    !S_ISDIR(sb.st_mode)) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: Units/ not found", b->name);
		capbundle_close(b);
		return (-1);
	}

	/* Parse the declared inventory in declaration order. */
	for (unsigned i = 0; i < b->nunit_names; i++) {
		if (snprintf(unit_dir, sizeof(unit_dir), "%s/%s.unit", units_dir,
		    b->unit_names[i]) >= (int)sizeof(unit_dir) ||
		    lstat(unit_dir, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
			if (errbuf != NULL)
				snprintf(errbuf, errlen,
				    "%s: declared unit '%s' is missing",
				    b->name, b->unit_names[i]);
			capbundle_close(b);
			return (-1);
		}
		if (snprintf(manifest_path, sizeof(manifest_path), "%s/Unit.ucl",
		    unit_dir) >= (int)sizeof(manifest_path) ||
		    capbundle_parse_unit_ucl(manifest_path, unit_dir, b,
		    b->unit_names[i], &b->services[i], errbuf, errlen) == -1) {
			if (errbuf != NULL && errlen > 0 && errbuf[0] == '\0')
				snprintf(errbuf, errlen,
				    "%s: Unit.ucl is empty or invalid", b->unit_names[i]);
			capbundle_close(b);
			return (-1);
		}
		b->nservices++;
	}

	/* Undeclared units are an error, not silently ignored policy. */
	d = opendir(units_dir);
	if (d == NULL) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: cannot open Units/: %s",
			    b->name, strerror(errno));
		capbundle_close(b);
		return (-1);
	}
	while ((de = readdir(d)) != NULL) {
		bool found;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		found = false;
		for (unsigned i = 0; i < b->nunit_names; i++) {
			char expected[CAPBUNDLE_NAME_MAX + 6];

			(void)snprintf(expected, sizeof(expected), "%s.unit",
			    b->unit_names[i]);
			if (strcmp(de->d_name, expected) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			if (errbuf != NULL)
				snprintf(errbuf, errlen,
				    "%s: undeclared entry in Units/: %s",
				    b->name, de->d_name);
			closedir(d);
			capbundle_close(b);
			return (-1);
		}
	}
	closedir(d);

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

	return (b != NULL ? b->bundle_id : NULL);
}

const char *
capbundle_version(const struct capbundle *b)
{

	return (b != NULL ? b->version : NULL);
}

const char *
capbundle_author(const struct capbundle *b)
{

	return (b != NULL ? b->author : NULL);
}

const char *
capbundle_publisher(const struct capbundle *b)
{

	return (b != NULL ? b->publisher : NULL);
}

uint64_t
capbundle_sequence(const struct capbundle *b)
{

	return (b != NULL ? b->sequence : 0);
}

const char *
capbundle_path(const struct capbundle *b)
{

	return (b != NULL ? b->path : NULL);
}

const char *
capbundle_name(const struct capbundle *b)
{

	return (b != NULL ? b->name : NULL);
}

unsigned
capbundle_nservices(const struct capbundle *b)
{

	return (b != NULL ? b->nservices : 0);
}

struct capbundle_service *
capbundle_service(const struct capbundle *b, unsigned idx)
{

	if (b == NULL || idx >= b->nservices)
		return (NULL);
	/* Safe: callers receive const pointer via the public API. */
	return (__DECONST(struct capbundle_service *, &b->services[idx]));
}

const char *
capbundle_svc_program(const struct capbundle_service *s)
{

	return (s != NULL ? s->program : NULL);
}

const char *
capbundle_svc_label(const struct capbundle_service *s)
{

	return (s != NULL ? s->label : NULL);
}

bool
capbundle_svc_activates_at_boot(const struct capbundle_service *s)
{

	return (s != NULL && s->activation_boot);
}

unsigned
capbundle_svc_nprovides(const struct capbundle_service *s)
{

	return (s != NULL ? s->nprovides : 0);
}

int
capbundle_svc_management_class(const struct capbundle_service *s)
{

	return (s != NULL ? s->management : CAPBUNDLE_MGMT_SYSTEM);
}

unsigned
capbundle_svc_timer_interval(const struct capbundle_service *s)
{

	return (s != NULL ? s->timer_interval_sec : 0);
}

const char *
capbundle_svc_activation_path(const struct capbundle_service *s)
{

	return (s != NULL ? s->activation_path : "");
}

unsigned
capbundle_svc_nactivation_sockets(const struct capbundle_service *s)
{

	return (s != NULL ? s->nactivation_sockets : 0);
}

const struct svc_activation_socket *
capbundle_svc_activation_socket(const struct capbundle_service *s, unsigned i)
{

	if (s == NULL || i >= s->nactivation_sockets)
		return (NULL);
	return (&s->activation_sockets[i]);
}

const char *
capbundle_svc_provides(const struct capbundle_service *s, unsigned idx)
{

	if (s == NULL || idx >= s->nprovides)
		return (NULL);
	return (s->provides[idx]);
}

unsigned
capbundle_svc_narguments(const struct capbundle_service *s)
{
	return (s != NULL ? s->narguments : 0);
}

const char *
capbundle_svc_argument(const struct capbundle_service *s, unsigned idx)
{
	return (s != NULL && idx < s->narguments ? s->arguments[idx] : NULL);
}

unsigned
capbundle_svc_nenvironment(const struct capbundle_service *s)
{
	return (s != NULL ? s->nenvironment : 0);
}

const char *
capbundle_svc_environment(const struct capbundle_service *s, unsigned idx)
{
	return (s != NULL && idx < s->nenvironment ? s->environment[idx] :
	    NULL);
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

	if (s == NULL || m == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (s->narguments > SERVICED_MAX_ARGUMENTS ||
	    s->nenvironment > SERVICED_MAX_ENVIRONMENT ||
	    s->nprovides > SERVICED_MAX_PROVIDES ||
	    s->ncap_paths > SERVICED_MAX_CAP_PATHS ||
	    s->ncap_files > SERVICED_MAX_CAP_FILES ||
	    s->ncap_net > SERVICED_MAX_CAP_NET ||
	    s->ncap_jail > SERVICED_MAX_CAP_JAIL ||
	    s->ncap_vsock > SERVICED_MAX_CAP_VSOCK ||
	    s->ncap_services > SERVICED_MAX_CAP_SERVICES ||
	    s->nactivation_sockets > SERVICED_MAX_ACTIVATION_SOCKETS) {
		errno = EOVERFLOW;
		return (-1);
	}
	memset(m, 0, sizeof(*m));

	if (manifest_copy(s->label, m->label, sizeof(m->label)) == -1 ||
	    manifest_copy(s->program, m->program, sizeof(m->program)) == -1 ||
	    manifest_copy(s->user, m->user, sizeof(m->user)) == -1 ||
	    manifest_copy(s->group, m->group, sizeof(m->group)) == -1)
		return (-1);
	m->narguments = s->narguments;
	for (i = 0; i < s->narguments; i++)
		if (manifest_copy(s->arguments[i], m->arguments[i],
		    sizeof(m->arguments[i])) == -1)
			return (-1);
	m->nenvironment = s->nenvironment;
	for (i = 0; i < s->nenvironment; i++)
		if (manifest_copy(s->environment[i], m->environment[i],
		    sizeof(m->environment[i])) == -1)
			return (-1);

	m->nprovides = s->nprovides;
	for (i = 0; i < s->nprovides && i < CAPBUNDLE_MAX_PROVIDES; i++) {
		if (manifest_copy(s->provides[i], m->provides[i],
		    sizeof(m->provides[i])) == -1)
			return (-1);
	}

	m->cap_system = s->cap_system;
	m->protect_flags = s->protect_flags;
	m->restart = s->restart;
	m->management = s->management;
	m->is_helper = s->is_helper;
	/*
	 * A private helper's synthetic bundle-local provider name
	 * ("helper.<bundle-id>.<unit>") is injected into provides[] at parse time
	 * (see libcapbundle_parse.c) so the bundle registry indexes it; the
	 * generic provides[] copy above already carried it into the manifest.
	 */
	m->timer_interval_sec = s->timer_interval_sec;
	if (manifest_copy(s->activation_path, m->activation_path,
	    sizeof(m->activation_path)) == -1)
		return (-1);
	m->nactivation_sockets = MIN(s->nactivation_sockets,
	    SERVICED_MAX_ACTIVATION_SOCKETS);
	for (i = 0; i < m->nactivation_sockets; i++)
		m->activation_sockets[i] = s->activation_sockets[i];
	m->stop_timeout = s->stop_timeout > 0 ? s->stop_timeout : 5;
	m->max_failures = s->max_failures > 0 ? s->max_failures : 10;
	m->privileged = s->privileged;

	/* Pre-exec process policy: limits / band / umask. */
	m->limits = s->limits;
	m->band = s->band;
	m->umask_val = s->umask_val;

	/* Calendar / queue-directory / mount activation sources. */
	m->has_calendar = s->has_calendar;
	m->calendar = s->calendar;
	m->calendar_persistent = s->calendar_persistent;
	if (manifest_copy(s->queue_directory, m->queue_directory,
	    sizeof(m->queue_directory)) == -1)
		return (-1);
	m->activation_on_mount = s->activation_on_mount;

	/* Path capabilities */
	m->ncap_paths = MIN(s->ncap_paths, SERVICED_MAX_CAP_PATHS);
	for (i = 0; i < m->ncap_paths; i++) {
		if (manifest_copy(s->cap_paths[i], m->cap_paths[i],
		    sizeof(m->cap_paths[i])) == -1)
			return (-1);
	}

	/* File capabilities */
	m->ncap_files = MIN(s->ncap_files, SERVICED_MAX_CAP_FILES);
	for (i = 0; i < m->ncap_files; i++) {
		if (manifest_copy(s->cap_files[i].path,
		    m->cap_files[i].path,
		    sizeof(m->cap_files[i].path)) == -1)
			return (-1);
		m->cap_files[i].actions = s->cap_files[i].actions;
	}

	/* Files/dirs serviced opens and delivers as named descriptors */
	m->ncap_open = MIN(s->ncap_open, SERVICED_MAX_CAP_OPEN);
	for (i = 0; i < m->ncap_open; i++) {
		if (manifest_copy(s->cap_open[i].path, m->cap_open[i].path,
		    sizeof(m->cap_open[i].path)) == -1)
			return (-1);
		if (manifest_copy(s->cap_open[i].name, m->cap_open[i].name,
		    sizeof(m->cap_open[i].name)) == -1)
			return (-1);
		m->cap_open[i].rights = s->cap_open[i].rights;
		m->cap_open[i].is_dir = s->cap_open[i].is_dir;
		m->cap_open[i].optional = s->cap_open[i].optional;
	}

	/* Network capabilities */
	m->ncap_net = MIN(s->ncap_net, SERVICED_MAX_CAP_NET);
	for (i = 0; i < m->ncap_net; i++)
		m->cap_net[i] = s->cap_net[i];

	/* Jail capabilities */
	m->ncap_jail = MIN(s->ncap_jail, SERVICED_MAX_CAP_JAIL);
	for (i = 0; i < m->ncap_jail; i++)
		m->cap_jail[i] = s->cap_jail[i];
	m->ncap_vsock = s->ncap_vsock;
	for (i = 0; i < m->ncap_vsock; i++)
		m->cap_vsock[i] = s->cap_vsock[i];
	m->ncap_services = s->ncap_services;
	for (i = 0; i < m->ncap_services; i++)
		if (manifest_copy(s->cap_services[i], m->cap_services[i],
		    sizeof(m->cap_services[i])) == -1)
			return (-1);

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

	if (dirpath == NULL || cb == NULL) {
		errno = EINVAL;
		return (-1);
	}
	d = opendir(dirpath);
	if (d == NULL)
		return (-1);

	while ((de = readdir(d)) != NULL) {
		if (!bundle_name_has_suffix(de->d_name))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);

		if (capbundle_open(path, &b, errbuf, sizeof(errbuf)) == -1) {
			syslog(LOG_WARNING, "capbundle scan: %s", errbuf);
			errno = EINVAL;
			closedir(d);
			return (-1);
		}

		ret = cb(b, ctx);
		if (ret != 0) {
			capbundle_close(b);
			closedir(d);
			return (ret);
		}
		/* Callback is responsible for closing b on success. */
	}

	closedir(d);
	return (0);
}
