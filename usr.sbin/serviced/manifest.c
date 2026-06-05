/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service manifest parser for serviced.
 *
 * Reads UCL manifests from the manifest directory and populates svc_manifest
 * structs.  Invalid manifests are logged and skipped.  Missing
 * directory is not an error (no services to start).
 */

#include <sys/socket.h>
#include <netinet/in.h>

#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include <dev/cap_rt/cap_rt_isolation_proto.h>

#include "claim_parse.h"
#include "serviced.h"
#include "gates.h"

static void
net_claim_port_string(const struct serviced_net_claim *nc, char *buf,
    size_t len)
{

	if (nc->port_min == 0 && nc->port_max == UINT16_MAX)
		strlcpy(buf, "*", len);
	else if (nc->port_min == nc->port_max)
		snprintf(buf, len, "%u", nc->port_min);
	else
		snprintf(buf, len, "%u-%u", nc->port_min, nc->port_max);
}

/*
 * Parse a UCL network claim object.
 * Intentionally duplicated from oracled/config.c because the struct
 * type differs (serviced_net_claim vs oracled_net_claim).  The field
 * layout is identical.
 */
static int
parse_ucl_net_claim(const ucl_object_t *elem, struct serviced_net_claim *nc,
    const char *label)
{
	const ucl_object_t *v;
	const char *s;

	memset(nc, 0, sizeof(*nc));
	nc->port_min = 0;
	nc->port_max = UINT16_MAX;

	v = ucl_object_lookup(elem, "port");
	if (v == NULL)
		v = ucl_object_lookup(elem, "ports");
	if (v != NULL) {
		if (parse_port_range_obj(v, &nc->port_min,
		    &nc->port_max) != 0) {
			syslog(LOG_WARNING, "%s: invalid port range", label);
			return (-1);
		}
	}

	v = ucl_object_lookup(elem, "protocol");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0)
			nc->protocol = 0;
		else if (strcmp(s, "tcp") == 0)
			nc->protocol = IPPROTO_TCP;
		else if (strcmp(s, "udp") == 0)
			nc->protocol = IPPROTO_UDP;
		else {
			syslog(LOG_ERR, "%s: unknown protocol: %s",
			    label, s);
			return (-1);
		}
	}

	v = ucl_object_lookup(elem, "direction");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "bind") == 0)
			nc->direction = SERVICED_NET_DIR_BIND;
		else if (strcmp(s, "connect") == 0)
			nc->direction = SERVICED_NET_DIR_CONNECT;
		else if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0)
			nc->direction = SERVICED_NET_DIR_ANY;
		else {
			syslog(LOG_ERR, "%s: unknown direction: %s",
			    label, s);
			return (-1);
		}
	}
	if (nc->direction == 0)
		nc->direction = SERVICED_NET_DIR_BIND;

	nc->domain = AF_INET;
	v = ucl_object_lookup(elem, "domain");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "inet") == 0)
			nc->domain = AF_INET;
		else if (strcmp(s, "inet6") == 0)
			nc->domain = AF_INET6;
		else if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0)
			nc->domain = 0;
		else {
			syslog(LOG_ERR, "%s: unknown domain: %s",
			    label, s);
			return (-1);
		}
	}

	return (0);
}

static int
parse_ucl_jail_claim(const ucl_object_t *elem, struct serviced_jail_claim *jc,
    const char *label)
{
	const ucl_object_t *v;
	int64_t jid;

	memset(jc, 0, sizeof(*jc));
	jc->actions = FI_JAIL_ALL;

	switch (ucl_object_type(elem)) {
	case UCL_INT:
		jid = ucl_object_toint(elem);
		if (jid <= 0 || jid > INT32_MAX)
			return (-1);
		jc->jid = (int32_t)jid;
		return (0);
	case UCL_STRING:
		if (strlcpy(jc->name, ucl_object_tostring(elem),
		    sizeof(jc->name)) >= sizeof(jc->name))
			return (-1);
		return (jc->name[0] != '\0' ? 0 : -1);
	case UCL_OBJECT:
		break;
	default:
		return (-1);
	}

	v = ucl_object_lookup(elem, "jid");
	if (v != NULL) {
		if (ucl_object_type(v) != UCL_INT)
			return (-1);
		jid = ucl_object_toint(v);
		if (jid <= 0 || jid > INT32_MAX)
			return (-1);
		jc->jid = (int32_t)jid;
	}
	v = ucl_object_lookup(elem, "name");
	if (v != NULL) {
		if (ucl_object_type(v) != UCL_STRING)
			return (-1);
		if (strlcpy(jc->name, ucl_object_tostring(v),
		    sizeof(jc->name)) >= sizeof(jc->name))
			return (-1);
	}
	v = ucl_object_lookup(elem, "actions");
	if (parse_jail_actions(v, &jc->actions) != 0) {
		syslog(LOG_WARNING, "manifest %s: invalid jail actions",
		    label);
		return (-1);
	}
	return ((jc->jid != 0 || jc->name[0] != '\0') ? 0 : -1);
}

/*
 * Copy a UCL string into a fixed buffer, rejecting truncation.
 * Returns 0 on success, -1 if the source was too long.
 */
static int
safe_copy(const char *src, char *dst, size_t dstsz, const char *field,
    const char *label, const char *path)
{

	if (strlcpy(dst, src, dstsz) >= dstsz) {
		syslog(LOG_ERR, "manifest %s: %s too long (max %zu): %s",
		    label[0] != '\0' ? label : path,
		    field, dstsz - 1, src);
		return (-1);
	}
	return (0);
}

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
parse_string_array(const ucl_object_t *arr, char (*out)[SERVICED_LABEL_MAX],
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
		if (strlcpy(out[*np], s, SERVICED_LABEL_MAX) >=
		    SERVICED_LABEL_MAX) {
			syslog(LOG_WARNING, "manifest %s: %s too long, "
			    "skipped: %s", label, what, s);
			continue;
		}
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
		if (m->ncap_paths >= SERVICED_MAX_CAP_PATHS) {
			syslog(LOG_WARNING, "manifest %s: too many "
			    "capability paths (max %d)", m->label,
			    SERVICED_MAX_CAP_PATHS);
			break;
		}
		if (strlcpy(m->cap_paths[m->ncap_paths], s,
		    PATH_MAX) >= PATH_MAX) {
			syslog(LOG_WARNING, "manifest %s: capability "
			    "path too long, skipped: %s", m->label, s);
			continue;
		}
		m->ncap_paths++;
	}
}

static void
parse_cap_files(const ucl_object_t *arr, struct svc_manifest *m)
{
	const ucl_object_t *elem, *pv, *av;
	ucl_object_iter_t it;

	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return;

	it = NULL;
	while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_OBJECT)
			continue;
		if (m->ncap_files >= SERVICED_MAX_CAP_FILES) {
			syslog(LOG_WARNING, "manifest %s: too many "
			    "file capabilities (max %d)", m->label,
			    SERVICED_MAX_CAP_FILES);
			break;
		}
		pv = ucl_object_lookup(elem, "path");
		if (pv == NULL || ucl_object_type(pv) != UCL_STRING)
			continue;
		if (ucl_object_tostring(pv)[0] != '/') {
			syslog(LOG_WARNING, "manifest %s: file capability "
			    "path must be absolute: %s", m->label,
			    ucl_object_tostring(pv));
			continue;
		}
		if (strlcpy(m->cap_files[m->ncap_files].path,
		    ucl_object_tostring(pv),
		    sizeof(m->cap_files[m->ncap_files].path)) >= PATH_MAX) {
			syslog(LOG_WARNING, "manifest %s: file capability "
			    "path too long, skipped: %s", m->label,
			    ucl_object_tostring(pv));
			continue;
		}
		av = ucl_object_lookup(elem, "actions");
		if (parse_file_actions(av,
		    &m->cap_files[m->ncap_files].actions) != 0) {
			syslog(LOG_ERR, "manifest %s: invalid file actions",
			    m->label);
			continue;
		}
		m->ncap_files++;
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
	const ucl_object_t *elem;
	ucl_object_iter_t it;

	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return;

	it = NULL;
	while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_OBJECT)
			continue;
		if (m->ncap_net >= SERVICED_MAX_CAP_NET) {
			syslog(LOG_WARNING, "manifest %s: too many "
			    "network capabilities (max %d)", m->label,
			    SERVICED_MAX_CAP_NET);
			break;
		}
		if (parse_ucl_net_claim(elem,
		    &m->cap_net[m->ncap_net], m->label) == 0)
			m->ncap_net++;
	}
}

static void
parse_cap_jails(const ucl_object_t *arr, struct svc_manifest *m)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it;

	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return;

	it = NULL;
	while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (m->ncap_jail >= SERVICED_MAX_CAP_JAIL) {
			syslog(LOG_WARNING, "manifest %s: too many "
			    "jail capabilities (max %d)", m->label,
			    SERVICED_MAX_CAP_JAIL);
			break;
		}
		if (parse_ucl_jail_claim(elem,
		    &m->cap_jail[m->ncap_jail], m->label) == 0)
			m->ncap_jail++;
		else
			syslog(LOG_WARNING, "manifest %s: invalid "
			    "jail capability", m->label);
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
	parse_cap_files(ucl_object_lookup(sec, "files"), m);
	parse_cap_network(ucl_object_lookup(sec, "network"), m);
	parse_cap_jails(ucl_object_lookup(sec, "jails"), m);
	parse_cap_system(ucl_object_lookup(sec, "system"), m);
}

/*
 * Parse a single manifest file into a svc_manifest struct.
 * Returns 0 on success, -1 on error (logged).
 */
int
manifest_load_file(const char *path, struct svc_manifest *m)
{
	struct ucl_parser *parser;
	const ucl_object_t *root, *o;
	const char *s;
	int rv;

	memset(m, 0, sizeof(*m));
	m->restart = SVC_RESTART_NEVER;
	m->stop_timeout = 5;
	m->max_failures = 10;

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
	if (safe_copy(ucl_object_tostring(o), m->label, sizeof(m->label),
	    "label", "", path) == -1)
		goto out;

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
	if (safe_copy(s, m->program, sizeof(m->program),
	    "program", m->label, path) == -1)
		goto out;

	/* Optional string fields — reject truncation on security-relevant ones. */
	o = ucl_object_lookup(root, "description");
	if (o != NULL && ucl_object_type(o) == UCL_STRING)
		strlcpy(m->description, ucl_object_tostring(o),
		    sizeof(m->description));  /* truncation OK for description */

	o = ucl_object_lookup(root, "user");
	if (o != NULL && ucl_object_type(o) == UCL_STRING) {
		if (safe_copy(ucl_object_tostring(o), m->user,
		    sizeof(m->user), "user", m->label, path) == -1)
			goto out;
	}

	o = ucl_object_lookup(root, "group");
	if (o != NULL && ucl_object_type(o) == UCL_STRING) {
		if (safe_copy(ucl_object_tostring(o), m->group,
		    sizeof(m->group), "group", m->label, path) == -1)
			goto out;
	}

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

	/* stop_timeout */
	o = ucl_object_lookup(root, "stop_timeout");
	if (o != NULL && ucl_object_type(o) == UCL_INT) {
		int64_t v = ucl_object_toint(o);
		if (v < 1)
			v = 1;
		if (v > 300)
			v = 300;
		m->stop_timeout = (int)v;
	}

	/* max_failures — circuit breaker threshold */
	o = ucl_object_lookup(root, "max_failures");
	if (o != NULL && ucl_object_type(o) == UCL_INT) {
		int64_t v = ucl_object_toint(o);
		if (v < 1)
			v = 1;
		if (v > 100)
			v = 100;
		m->max_failures = (unsigned)v;
	}

	/* provides / requires */
	parse_string_array(ucl_object_lookup(root, "provides"),
	    m->provides, SERVICED_MAX_PROVIDES, &m->nprovides,
	    "provides", m->label);
	parse_string_array(ucl_object_lookup(root, "requires"),
	    m->requires, SERVICED_MAX_REQUIRES, &m->nrequires,
	    "requires", m->label);

	/* capabilities */
	parse_capabilities(root, m);

	/* jail section — optional jail to create and attach into */
	{
		const ucl_object_t *jail_sec, *jv;
		const char *js;

		jail_sec = ucl_object_lookup(root, "jail");
		if (jail_sec != NULL &&
		    ucl_object_type(jail_sec) == UCL_OBJECT) {
			jv = ucl_object_lookup(jail_sec, "name");
			if (jv == NULL || ucl_object_type(jv) != UCL_STRING ||
			    ucl_object_tostring(jv)[0] == '\0') {
				syslog(LOG_ERR, "manifest %s: jail section "
				    "requires name", m->label);
				goto out;
			}
			if (safe_copy(ucl_object_tostring(jv), m->jail_name,
			    sizeof(m->jail_name), "jail.name", m->label,
			    path) == -1)
				goto out;

			jv = ucl_object_lookup(jail_sec, "path");
			if (jv == NULL || ucl_object_type(jv) != UCL_STRING) {
				syslog(LOG_ERR, "manifest %s: jail section "
				    "requires path", m->label);
				goto out;
			}
			js = ucl_object_tostring(jv);
			if (js[0] != '/') {
				syslog(LOG_ERR, "manifest %s: jail.path must "
				    "be absolute: %s", m->label, js);
				goto out;
			}
			if (safe_copy(js, m->jail_path, sizeof(m->jail_path),
			    "jail.path", m->label, path) == -1)
				goto out;

			jv = ucl_object_lookup(jail_sec, "hostname");
			if (jv != NULL && ucl_object_type(jv) == UCL_STRING) {
				if (safe_copy(ucl_object_tostring(jv),
				    m->jail_hostname,
				    sizeof(m->jail_hostname),
				    "jail.hostname", m->label, path) == -1)
					goto out;
			}

			jv = ucl_object_lookup(jail_sec, "ip4");
			if (jv != NULL && ucl_object_type(jv) == UCL_STRING) {
				if (safe_copy(ucl_object_tostring(jv),
				    m->jail_ip4_addr,
				    sizeof(m->jail_ip4_addr),
				    "jail.ip4", m->label, path) == -1)
					goto out;
			}

			m->has_jail = true;
		}
	}

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
	char *names[SERVICED_MAX_SERVICES];
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
		if (nnames >= SERVICED_MAX_SERVICES) {
			syslog(LOG_WARNING, "manifest: too many files in "
			    "%s (max %d)", dirpath, SERVICED_MAX_SERVICES);
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
log_label_list(const char *prefix, const char (*names)[SERVICED_LABEL_MAX],
    unsigned count)
{
	char buf[512];
	size_t off;
	unsigned i;

	off = 0;
	for (i = 0; i < count; i++)
		BUF_APPEND(buf, sizeof(buf), &off, "%s%s",
		    i > 0 ? " " : "", names[i]);
	syslog(LOG_INFO, "    %s: %s", prefix, buf);
}

void
manifest_log(const struct svc_manifest *m)
{

	syslog(LOG_INFO, "  service: %s program=%s restart=%s",
	    m->label, m->program,
	    restart_policy_name(m->restart));
	if (m->nprovides > 0)
		log_label_list("provides", m->provides, m->nprovides);
	if (m->nrequires > 0)
		log_label_list("requires", m->requires, m->nrequires);
	if (m->ncap_paths > 0 || m->ncap_files > 0 || m->ncap_net > 0 ||
	    m->ncap_jail > 0 || m->cap_system != 0)
		syslog(LOG_INFO, "    capabilities: paths=%u files=%u "
		    "network=%u jails=%u system=0x%x", m->ncap_paths,
		    m->ncap_files, m->ncap_net, m->ncap_jail, m->cap_system);
	if (m->has_jail)
		syslog(LOG_INFO, "    jail: %s path=%s", m->jail_name,
		    m->jail_path);
}

/*
 * Validate a parsed manifest for runtime correctness:
 * program must exist and be executable, user/group must resolve.
 * Returns 0 on success, -1 with error message in errbuf.
 */
int
manifest_validate(const struct svc_manifest *m, char *errbuf, size_t errlen)
{

	if (access(m->program, X_OK) != 0) {
		snprintf(errbuf, errlen, "program \"%s\": %s",
		    m->program, strerror(errno));
		return (-1);
	}

	/*
	 * User/group validation is deferred to svc_exec() time.
	 * getpwnam/getgrnam can block on NIS/LDAP and must not
	 * run in the event loop (reload/check paths).  svc_exec()
	 * already resolves credentials before fork and fails with
	 * a clear error if the user/group does not exist.
	 */

	return (0);
}

/*
 * Format a human-readable summary of a manifest into buf.
 * Returns the number of bytes written (excluding NUL).
 */
int
manifest_format_summary(const struct svc_manifest *m, char *buf, size_t len)
{
	size_t off;
	unsigned i;

	if (len == 0)
		return (0);

	off = 0;

	BUF_APPEND(buf, len, &off, "%s:\n", m->label);
	BUF_APPEND(buf, len, &off, "  program:      %s\n", m->program);

	if (m->description[0] != '\0')
		BUF_APPEND(buf, len, &off,"  description:  %s\n", m->description);
	if (m->user[0] != '\0')
		BUF_APPEND(buf, len, &off,"  user:         %s\n", m->user);
	if (m->group[0] != '\0')
		BUF_APPEND(buf, len, &off,"  group:        %s\n", m->group);

	BUF_APPEND(buf, len, &off,"  restart:      %s\n",
	    restart_policy_name(m->restart));

	if (m->nprovides > 0) {
		BUF_APPEND(buf, len, &off,"  provides:     [");
		for (i = 0; i < m->nprovides; i++)
			BUF_APPEND(buf, len, &off,"%s%s", i > 0 ? ", " : "",
			    m->provides[i]);
		BUF_APPEND(buf, len, &off,"]\n");
	}

	if (m->nrequires > 0) {
		BUF_APPEND(buf, len, &off,"  requires:     [");
		for (i = 0; i < m->nrequires; i++)
			BUF_APPEND(buf, len, &off,"%s%s", i > 0 ? ", " : "",
			    m->requires[i]);
		BUF_APPEND(buf, len, &off,"]\n");
	}

	if (m->ncap_paths > 0 || m->ncap_files > 0 || m->ncap_net > 0 ||
	    m->ncap_jail > 0 || m->cap_system != 0)
		BUF_APPEND(buf, len, &off,"  capabilities:\n");

	for (i = 0; i < m->ncap_paths; i++)
		BUF_APPEND(buf, len, &off,"    path:       %s\n", m->cap_paths[i]);

	for (i = 0; i < m->ncap_files; i++)
		BUF_APPEND(buf, len, &off,"    file:       %s actions=0x%jx\n",
		    m->cap_files[i].path,
		    (uintmax_t)m->cap_files[i].actions);

	for (i = 0; i < m->ncap_net; i++) {
		const struct serviced_net_claim *nc = &m->cap_net[i];
		char portbuf[32];

		net_claim_port_string(nc, portbuf, sizeof(portbuf));
		BUF_APPEND(buf, len, &off,"    network:    %s/%s %s\n",
		    net_protocol_name(nc->protocol),
		    portbuf,
		    net_direction_name(nc->direction));
	}

	for (i = 0; i < m->ncap_jail; i++) {
		const struct serviced_jail_claim *jc = &m->cap_jail[i];

		if (jc->jid != 0 && jc->name[0] != '\0')
			BUF_APPEND(buf, len, &off,
			    "    jail:       %s#%d actions=0x%x\n",
			    jc->name, jc->jid, jc->actions);
		else if (jc->jid != 0)
			BUF_APPEND(buf, len, &off,
			    "    jail:       #%d actions=0x%x\n",
			    jc->jid, jc->actions);
		else
			BUF_APPEND(buf, len, &off,
			    "    jail:       %s actions=0x%x\n",
			    jc->name, jc->actions);
	}

	if (m->cap_system != 0)
		BUF_APPEND(buf, len, &off,"    system:     0x%x\n", m->cap_system);

	return ((int)off);
}
