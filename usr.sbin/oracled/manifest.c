/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service manifest parser for oracled.
 *
 * Reads UCL manifests from /etc/oracled.d/ and populates svc_manifest
 * structs.  Invalid manifests are logged and skipped.  Missing
 * directory is not an error (no services to start).
 */

#include <sys/socket.h>
#include <netinet/in.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include "oracled.h"
#include "gates.h"

static int
parse_restart(const char *s)
{

	if (strcmp(s, "always") == 0)
		return (SVC_RESTART_ALWAYS);
	if (strcmp(s, "on-failure") == 0)
		return (SVC_RESTART_ON_FAILURE);
	if (strcmp(s, "never") == 0)
		return (SVC_RESTART_NEVER);
	return (-1);
}

static void
parse_string_array(const ucl_object_t *arr, char (*out)[ORACLED_LABEL_MAX],
    unsigned maxn, unsigned *np, const char *what, const char *label)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it;
	const char *s;

	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return;

	it = NULL;
	while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_STRING)
			continue;
		s = ucl_object_tostring(elem);
		if (s[0] == '\0')
			continue;
		if (*np >= maxn) {
			syslog(LOG_WARNING, "manifest %s: too many %s "
			    "(max %u)", label, what, maxn);
			break;
		}
		strlcpy(out[*np], s, ORACLED_LABEL_MAX);
		(*np)++;
	}
}

static void
parse_cap_paths(const ucl_object_t *arr, struct svc_manifest *m)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it;
	const char *s;

	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return;

	it = NULL;
	while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_STRING)
			continue;
		s = ucl_object_tostring(elem);
		if (s[0] != '/') {
			syslog(LOG_WARNING, "manifest %s: capability path "
			    "must be absolute: %s", m->label, s);
			continue;
		}
		if (m->ncap_paths >= ORACLED_MAX_CAP_PATHS) {
			syslog(LOG_WARNING, "manifest %s: too many "
			    "capability paths (max %d)", m->label,
			    ORACLED_MAX_CAP_PATHS);
			break;
		}
		strlcpy(m->cap_paths[m->ncap_paths], s, PATH_MAX);
		m->ncap_paths++;
	}
}

static void
parse_cap_system(const ucl_object_t *arr, struct svc_manifest *m)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it;
	const char *s;
	unsigned gi;
	bool found;

	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return;

	it = NULL;
	while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_STRING)
			continue;
		s = ucl_object_tostring(elem);
		found = false;
		for (gi = 0; gi < nitems(gate_names); gi++) {
			if (strcmp(s, gate_names[gi].name) == 0) {
				m->cap_system |= gate_names[gi].gate;
				found = true;
				break;
			}
		}
		if (!found)
			syslog(LOG_WARNING, "manifest %s: unknown "
			    "system gate: %s", m->label, s);
	}
}

static void
parse_cap_network(const ucl_object_t *arr, struct svc_manifest *m)
{
	const ucl_object_t *elem, *v;
	ucl_object_iter_t it;
	const char *s;

	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return;

	it = NULL;
	while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		struct oracled_net_claim *nc;

		if (ucl_object_type(elem) != UCL_OBJECT)
			continue;
		if (m->ncap_net >= ORACLED_MAX_CAP_NET) {
			syslog(LOG_WARNING, "manifest %s: too many "
			    "network capabilities (max %d)", m->label,
			    ORACLED_MAX_CAP_NET);
			break;
		}
		nc = &m->cap_net[m->ncap_net];
		memset(nc, 0, sizeof(*nc));

		v = ucl_object_lookup(elem, "port");
		if (v != NULL && ucl_object_type(v) == UCL_INT) {
			int64_t pv = ucl_object_toint(v);
			if (pv < 0 || pv > 65535) {
				syslog(LOG_WARNING, "manifest %s: invalid "
				    "port: %jd", m->label, (intmax_t)pv);
				continue;
			}
			nc->port = (uint16_t)pv;
		}

		v = ucl_object_lookup(elem, "protocol");
		if (v != NULL && ucl_object_type(v) == UCL_STRING) {
			s = ucl_object_tostring(v);
			if (strcmp(s, "tcp") == 0)
				nc->protocol = IPPROTO_TCP;
			else if (strcmp(s, "udp") == 0)
				nc->protocol = IPPROTO_UDP;
			else
				syslog(LOG_WARNING, "manifest %s: unknown "
				    "protocol: %s", m->label, s);
		}

		v = ucl_object_lookup(elem, "direction");
		if (v != NULL && ucl_object_type(v) == UCL_STRING) {
			s = ucl_object_tostring(v);
			if (strcmp(s, "bind") == 0)
				nc->direction = 0x01;
			else if (strcmp(s, "connect") == 0)
				nc->direction = 0x02;
			else if (strcmp(s, "any") == 0)
				nc->direction = 0x03;
		}
		if (nc->direction == 0)
			nc->direction = 0x01;

		nc->domain = AF_INET;
		v = ucl_object_lookup(elem, "domain");
		if (v != NULL && ucl_object_type(v) == UCL_STRING) {
			s = ucl_object_tostring(v);
			if (strcmp(s, "inet6") == 0)
				nc->domain = AF_INET6;
			else if (strcmp(s, "any") == 0)
				nc->domain = 0;
		}

		m->ncap_net++;
	}
}

static void
parse_capabilities(const ucl_object_t *root, struct svc_manifest *m)
{
	const ucl_object_t *sec;

	sec = ucl_object_lookup(root, "capabilities");
	if (sec == NULL || ucl_object_type(sec) != UCL_OBJECT)
		return;

	parse_cap_paths(ucl_object_lookup(sec, "paths"), m);
	parse_cap_network(ucl_object_lookup(sec, "network"), m);
	parse_cap_system(ucl_object_lookup(sec, "system"), m);
}

/*
 * Parse a single manifest file into a svc_manifest struct.
 * Returns 0 on success, -1 on error (logged).
 */
static int
manifest_load_file(const char *path, struct svc_manifest *m)
{
	struct ucl_parser *parser;
	const ucl_object_t *root, *o;
	const char *s;
	int rv;

	memset(m, 0, sizeof(*m));
	m->restart = SVC_RESTART_NEVER;

	parser = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (parser == NULL) {
		syslog(LOG_ERR, "manifest: ucl_parser_new failed for %s",
		    path);
		return (-1);
	}

	if (!ucl_parser_add_file(parser, path)) {
		syslog(LOG_ERR, "manifest: %s: %s", path,
		    ucl_parser_get_error(parser));
		ucl_parser_free(parser);
		return (-1);
	}

	root = ucl_parser_get_object(parser);
	if (root == NULL) {
		syslog(LOG_ERR, "manifest: %s: empty", path);
		ucl_parser_free(parser);
		return (-1);
	}

	rv = -1;

	/* label (required) */
	o = ucl_object_lookup(root, "label");
	if (o == NULL || ucl_object_type(o) != UCL_STRING ||
	    ucl_object_tostring(o)[0] == '\0') {
		syslog(LOG_ERR, "manifest: %s: missing or empty label", path);
		goto out;
	}
	strlcpy(m->label, ucl_object_tostring(o), sizeof(m->label));

	/* program (required, absolute path) */
	o = ucl_object_lookup(root, "program");
	if (o == NULL || ucl_object_type(o) != UCL_STRING) {
		syslog(LOG_ERR, "manifest %s: missing program", m->label);
		goto out;
	}
	s = ucl_object_tostring(o);
	if (s[0] != '/') {
		syslog(LOG_ERR, "manifest %s: program must be absolute: %s",
		    m->label, s);
		goto out;
	}
	strlcpy(m->program, s, sizeof(m->program));

	/* Optional string fields */
	o = ucl_object_lookup(root, "description");
	if (o != NULL && ucl_object_type(o) == UCL_STRING)
		strlcpy(m->description, ucl_object_tostring(o),
		    sizeof(m->description));

	o = ucl_object_lookup(root, "user");
	if (o != NULL && ucl_object_type(o) == UCL_STRING)
		strlcpy(m->user, ucl_object_tostring(o), sizeof(m->user));

	o = ucl_object_lookup(root, "group");
	if (o != NULL && ucl_object_type(o) == UCL_STRING)
		strlcpy(m->group, ucl_object_tostring(o), sizeof(m->group));

	o = ucl_object_lookup(root, "jail");
	if (o != NULL && ucl_object_type(o) == UCL_STRING)
		strlcpy(m->jail, ucl_object_tostring(o), sizeof(m->jail));

	/* restart policy */
	o = ucl_object_lookup(root, "restart");
	if (o != NULL && ucl_object_type(o) == UCL_STRING) {
		int rp = parse_restart(ucl_object_tostring(o));
		if (rp < 0)
			syslog(LOG_WARNING, "manifest %s: unknown restart "
			    "policy: %s", m->label, ucl_object_tostring(o));
		else
			m->restart = rp;
	}

	/* provides / requires */
	parse_string_array(ucl_object_lookup(root, "provides"),
	    m->provides, ORACLED_MAX_PROVIDES, &m->nprovides,
	    "provides", m->label);
	parse_string_array(ucl_object_lookup(root, "requires"),
	    m->requires, ORACLED_MAX_REQUIRES, &m->nrequires,
	    "requires", m->label);

	/* capabilities */
	parse_capabilities(root, m);

	rv = 0;
out:
	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(parser);
	return (rv);
}

static int
name_cmp(const void *a, const void *b)
{

	return (strcmp(*(const char *const *)a, *(const char *const *)b));
}

int
manifest_load_dir(const char *dirpath,
    struct svc_manifest *out, unsigned maxsvc, unsigned *nsvc)
{
	DIR *d;
	struct dirent *de;
	char path[PATH_MAX];
	char *names[ORACLED_MAX_SERVICES];
	unsigned nnames, i;
	size_t len;

	*nsvc = 0;
	nnames = 0;

	d = opendir(dirpath);
	if (d == NULL) {
		if (errno == ENOENT) {
			syslog(LOG_INFO, "manifest: %s not found, "
			    "no services", dirpath);
			return (0);
		}
		syslog(LOG_ERR, "manifest: opendir %s: %m", dirpath);
		return (-1);
	}

	/* Collect .ucl filenames. */
	while ((de = readdir(d)) != NULL) {
		len = strlen(de->d_name);
		if (len < 5 || strcmp(de->d_name + len - 4, ".ucl") != 0)
			continue;
		if (nnames >= ORACLED_MAX_SERVICES) {
			syslog(LOG_WARNING, "manifest: too many files in "
			    "%s (max %d)", dirpath, ORACLED_MAX_SERVICES);
			break;
		}
		names[nnames] = strdup(de->d_name);
		if (names[nnames] == NULL) {
			syslog(LOG_ERR, "manifest: strdup: %m");
			break;
		}
		nnames++;
	}
	closedir(d);

	/* Sort for deterministic load order. */
	qsort(names, nnames, sizeof(names[0]), name_cmp);

	/* Parse each file. */
	for (i = 0; i < nnames; i++) {
		if (*nsvc >= maxsvc) {
			syslog(LOG_WARNING, "manifest: service limit "
			    "reached (%u)", maxsvc);
			break;
		}
		snprintf(path, sizeof(path), "%s/%s", dirpath, names[i]);
		if (manifest_load_file(path, &out[*nsvc]) == 0) {
			syslog(LOG_INFO, "manifest: loaded %s", out[*nsvc].label);
			(*nsvc)++;
		}
	}

	/* Clean up name list. */
	for (i = 0; i < nnames; i++)
		free(names[i]);

	syslog(LOG_INFO, "manifest: %u services loaded from %s",
	    *nsvc, dirpath);
	return (0);
}

static void
log_label_list(const char *prefix, const char (*names)[ORACLED_LABEL_MAX],
    unsigned count)
{
	char buf[512];
	size_t off;
	unsigned i;

	off = 0;
	for (i = 0; i < count && off < sizeof(buf) - 1; i++) {
		if (i > 0 && off < sizeof(buf) - 1)
			buf[off++] = ' ';
		off += strlcpy(buf + off, names[i], sizeof(buf) - off);
	}
	buf[off] = '\0';
	syslog(LOG_INFO, "    %s: %s", prefix, buf);
}

void
manifest_log(const struct svc_manifest *m)
{

	syslog(LOG_INFO, "  service: %s program=%s restart=%s%s%s",
	    m->label, m->program,
	    m->restart == SVC_RESTART_ALWAYS ? "always" :
	    m->restart == SVC_RESTART_ON_FAILURE ? "on-failure" : "never",
	    m->jail[0] != '\0' ? " jail=" : "",
	    m->jail[0] != '\0' ? m->jail : "");
	if (m->nprovides > 0)
		log_label_list("provides", m->provides, m->nprovides);
	if (m->nrequires > 0)
		log_label_list("requires", m->requires, m->nrequires);
	if (m->ncap_paths > 0 || m->ncap_net > 0 || m->cap_system != 0)
		syslog(LOG_INFO, "    capabilities: paths=%u network=%u "
		    "system=0x%x", m->ncap_paths, m->ncap_net,
		    m->cap_system);
}
