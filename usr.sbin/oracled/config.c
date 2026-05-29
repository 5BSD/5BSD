/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * UCL configuration file parser for oracled.
 *
 * Reads /etc/oracled.conf (or a path given with -f) and populates
 * struct oracled_config.  Missing or empty file is not an error —
 * defaults apply.  Syntax errors are fatal.
 */

#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "config.h"

/*
 * Parse a single UCL network claim object into an oracled_net_claim.
 * Shared between config.c and manifest.c.
 * Returns 0 on success, -1 to skip this entry (bad port).
 */
int
parse_ucl_net_claim(const ucl_object_t *elem, struct oracled_net_claim *nc,
    const char *label)
{
	const ucl_object_t *v;
	const char *s;

	memset(nc, 0, sizeof(*nc));

	v = ucl_object_lookup(elem, "port");
	if (v != NULL && ucl_object_type(v) == UCL_INT) {
		int64_t pv = ucl_object_toint(v);
		if (pv < 0 || pv > 65535) {
			syslog(LOG_WARNING, "%s: invalid port: %jd",
			    label, (intmax_t)pv);
			return (-1);
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
			syslog(LOG_WARNING, "%s: unknown protocol: %s",
			    label, s);
	}

	v = ucl_object_lookup(elem, "direction");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "bind") == 0)
			nc->direction = ORACLED_NET_DIR_BIND;
		else if (strcmp(s, "connect") == 0)
			nc->direction = ORACLED_NET_DIR_CONNECT;
		else if (strcmp(s, "any") == 0)
			nc->direction = ORACLED_NET_DIR_ANY;
	}
	if (nc->direction == 0)
		nc->direction = ORACLED_NET_DIR_BIND;

	nc->domain = AF_INET;
	v = ucl_object_lookup(elem, "domain");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "inet6") == 0)
			nc->domain = AF_INET6;
		else if (strcmp(s, "any") == 0)
			nc->domain = 0;
	}

	return (0);
}
#include "gates.h"
#include "oracled_ctl.h"

void
config_init_defaults(struct oracled_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	strlcpy(cfg->pidfile, ORACLED_DEFAULT_PIDFILE,
	    sizeof(cfg->pidfile));
	strlcpy(cfg->control_socket, ORACLED_CTL_SOCK,
	    sizeof(cfg->control_socket));
	cfg->control_socket_mode = ORACLED_DEFAULT_CTLMODE;

	strlcpy(cfg->manifest_dir, ORACLED_DEFAULT_MANIFEST_DIR,
	    sizeof(cfg->manifest_dir));

	/* Integrity defaults: conservative — don't break rc(8). */
	cfg->integrity_ptrace = true;
	cfg->integrity_signal = false;
	cfg->integrity_visible = false;
	cfg->integrity_wait = true;
	cfg->integrity_sched = true;
	cfg->integrity_core = false;
	cfg->integrity_ktrace = true;
}

static void
cfg_bool(const ucl_object_t *obj, const char *key, bool *val)
{
	const ucl_object_t *o;

	o = ucl_object_lookup(obj, key);
	if (o != NULL && ucl_object_type(o) == UCL_BOOLEAN)
		*val = ucl_object_toboolean(o);
}

static void
cfg_string(const ucl_object_t *obj, const char *key,
    char *buf, size_t bufsz)
{
	const ucl_object_t *o;

	o = ucl_object_lookup(obj, key);
	if (o != NULL && ucl_object_type(o) == UCL_STRING)
		strlcpy(buf, ucl_object_tostring(o), bufsz);
}

static void
cfg_mode(const ucl_object_t *root, struct oracled_config *cfg)
{
	const ucl_object_t *o;
	long val;
	char *endp;

	o = ucl_object_lookup(root, "control_socket_mode");
	if (o == NULL)
		return;

	if (ucl_object_type(o) == UCL_STRING) {
		const char *ms = ucl_object_tostring(o);
		if (ms[0] == '\0') {
			fprintf(stderr, "oracled: empty "
			    "control_socket_mode\n");
			return;
		}
		errno = 0;
		val = strtol(ms, &endp, 0);
		if (endp == ms || *endp != '\0' || errno == ERANGE ||
		    val < 0 || val > 07777) {
			fprintf(stderr, "oracled: invalid "
			    "control_socket_mode: %s\n", ms);
			return;
		}
	} else if (ucl_object_type(o) == UCL_INT) {
		/*
		 * Integer mode is ambiguous: 700 is decimal, not
		 * octal 0700.  Reject and require a quoted string.
		 */
		fprintf(stderr, "oracled: control_socket_mode must be "
		    "a quoted string (e.g., \"0700\"), not an integer\n");
		return;
	} else {
		return;
	}

	if ((val & 07) != 0)
		fprintf(stderr, "oracled: warning: control_socket_mode "
		    "%04lo is world-accessible\n", val);

	cfg->control_socket_mode = (mode_t)val;
}

static void
cfg_integrity(const ucl_object_t *root, struct oracled_config *cfg)
{
	const ucl_object_t *sec;

	sec = ucl_object_lookup(root, "integrity");
	if (sec == NULL || ucl_object_type(sec) != UCL_OBJECT)
		return;

	cfg_bool(sec, "ptrace", &cfg->integrity_ptrace);
	cfg_bool(sec, "signal", &cfg->integrity_signal);
	cfg_bool(sec, "visible", &cfg->integrity_visible);
	cfg_bool(sec, "wait", &cfg->integrity_wait);
	cfg_bool(sec, "sched", &cfg->integrity_sched);
	cfg_bool(sec, "core", &cfg->integrity_core);
	cfg_bool(sec, "ktrace", &cfg->integrity_ktrace);
}

static void
cfg_claims(const ucl_object_t *root, struct oracled_config *cfg)
{
	const ucl_object_t *sec, *arr, *elem, *v;
	ucl_object_iter_t it;
	const char *s;

	sec = ucl_object_lookup(root, "claims");
	if (sec == NULL || ucl_object_type(sec) != UCL_OBJECT)
		return;

	/* claims.paths — string array */
	arr = ucl_object_lookup(sec, "paths");
	if (arr != NULL && ucl_object_type(arr) == UCL_ARRAY) {
		it = NULL;
		while ((elem = ucl_object_iterate(arr, &it, true))
		    != NULL) {
			if (ucl_object_type(elem) != UCL_STRING)
				continue;
			s = ucl_object_tostring(elem);
			if (s[0] == '\0')
				continue;
			if (s[0] != '/') {
				fprintf(stderr, "oracled: claim path "
				    "must be absolute: %s\n", s);
				continue;
			}
			if (cfg->nclaim_paths >= ORACLED_MAX_PATH_CLAIMS) {
				fprintf(stderr, "oracled: too many "
				    "claim paths (max %d)\n",
				    ORACLED_MAX_PATH_CLAIMS);
				break;
			}
			strlcpy(cfg->claim_paths[cfg->nclaim_paths],
			    s, PATH_MAX);
			cfg->nclaim_paths++;
		}
	}

	/* claims.network — array of objects */
	arr = ucl_object_lookup(sec, "network");
	if (arr != NULL && ucl_object_type(arr) == UCL_ARRAY) {
		it = NULL;
		while ((elem = ucl_object_iterate(arr, &it, true))
		    != NULL) {
			if (ucl_object_type(elem) != UCL_OBJECT)
				continue;
			if (cfg->nclaim_net >= ORACLED_MAX_NET_CLAIMS) {
				fprintf(stderr, "oracled: too many "
				    "network claims (max %d)\n",
				    ORACLED_MAX_NET_CLAIMS);
				break;
			}
			if (parse_ucl_net_claim(elem,
			    &cfg->claim_net[cfg->nclaim_net],
			    "config") == 0)
				cfg->nclaim_net++;
		}
	}

	/* claims.system — string array of gate names */
	arr = ucl_object_lookup(sec, "system");
	if (arr != NULL && ucl_object_type(arr) == UCL_ARRAY) {
		it = NULL;
		while ((elem = ucl_object_iterate(arr, &it, true))
		    != NULL) {
			unsigned gi;
			bool found;

			if (ucl_object_type(elem) != UCL_STRING)
				continue;
			s = ucl_object_tostring(elem);
			found = false;
			for (gi = 0; gi < nitems(gate_names); gi++) {
				if (strcmp(s, gate_names[gi].name) == 0) {
					cfg->claim_system |=
					    gate_names[gi].gate;
					found = true;
					break;
				}
			}
			if (!found)
				fprintf(stderr, "oracled: unknown "
				    "system gate: %s\n", s);
		}
	}
}

int
config_load(struct oracled_config *cfg, const char *path)
{
	struct ucl_parser *parser;
	const ucl_object_t *root;

	if (access(path, R_OK) != 0) {
		if (errno == ENOENT)
			return (0);
		fprintf(stderr, "oracled: %s: %s\n", path, strerror(errno));
		return (-1);
	}

	parser = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (parser == NULL) {
		fprintf(stderr, "oracled: ucl_parser_new failed\n");
		return (-1);
	}

	if (!ucl_parser_add_file(parser, path)) {
		fprintf(stderr, "oracled: %s: %s\n", path,
		    ucl_parser_get_error(parser));
		ucl_parser_free(parser);
		return (-1);
	}

	root = ucl_parser_get_object(parser);
	if (root == NULL) {
		ucl_parser_free(parser);
		cfg->loaded_from_file = true;
		return (0);
	}

	/* Top-level keys */
	cfg_string(root, "pidfile", cfg->pidfile, sizeof(cfg->pidfile));
	cfg_string(root, "control_socket", cfg->control_socket,
	    sizeof(cfg->control_socket));
	cfg_string(root, "manifest_dir", cfg->manifest_dir,
	    sizeof(cfg->manifest_dir));
	cfg_mode(root, cfg);

	/* Sections */
	cfg_integrity(root, cfg);
	cfg_claims(root, cfg);

	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(parser);

	cfg->loaded_from_file = true;
	return (0);
}

void
config_log(const struct oracled_config *cfg)
{

	if (cfg->loaded_from_file)
		syslog(LOG_INFO, "config: loaded from file");
	else
		syslog(LOG_INFO, "config: using defaults");
	syslog(LOG_INFO, "config: pidfile=%s", cfg->pidfile);
	syslog(LOG_INFO, "config: control_socket=%s mode=%04o",
	    cfg->control_socket, cfg->control_socket_mode);
	syslog(LOG_INFO, "config: integrity ptrace=%d signal=%d "
	    "visible=%d wait=%d sched=%d core=%d ktrace=%d",
	    cfg->integrity_ptrace, cfg->integrity_signal,
	    cfg->integrity_visible, cfg->integrity_wait,
	    cfg->integrity_sched, cfg->integrity_core,
	    cfg->integrity_ktrace);
	syslog(LOG_INFO, "config: manifest_dir=%s", cfg->manifest_dir);
	syslog(LOG_INFO, "config: claims paths=%d network=%d system=0x%x",
	    cfg->nclaim_paths, cfg->nclaim_net, cfg->claim_system);
}
