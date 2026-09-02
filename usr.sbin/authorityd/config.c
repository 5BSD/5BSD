/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * UCL configuration file parser for authorityd.
 *
 * Reads /etc/authorityd.conf (or a path given with -f) and populates
 * struct authorityd_config.  Missing or empty file is not an error —
 * defaults apply.  Syntax errors are fatal.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include "claim_parse.h"
#include "config.h"
#include "gates.h"
#include "authorityd_ctl.h"

/*
 * Parse a single UCL network claim object into an ort_net_claim.
 * Shared between config.c and manifest.c.
 * Returns 0 on success, -1 to skip this entry (bad port).
 */
int
parse_ucl_net_claim(const ucl_object_t *elem, struct ort_net_claim *nc,
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
		if (parse_net_protocol_string(s, &nc->protocol) != 0) {
			syslog(LOG_ERR, "%s: unknown protocol: %s",
			    label, s);
			return (-1);
		}
	}

	v = ucl_object_lookup(elem, "direction");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "bind") == 0)
			nc->direction = ORT_NET_DIR_BIND;
		else if (strcmp(s, "connect") == 0)
			nc->direction = ORT_NET_DIR_CONNECT;
		else if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0)
			nc->direction = ORT_NET_DIR_ANY;
		else {
			syslog(LOG_ERR, "%s: unknown direction: %s",
			    label, s);
			return (-1);
		}
	}
	if (nc->direction == 0)
		nc->direction = ORT_NET_DIR_BIND;

	nc->domain = AF_INET;
	v = ucl_object_lookup(elem, "domain");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "inet") == 0)
			nc->domain = AF_INET;
		else if (strcmp(s, "inet6") == 0)
			nc->domain = AF_INET6;
		else if (strcmp(s, "bluetooth") == 0)
			nc->domain = AF_BLUETOOTH;
		else if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0)
			nc->domain = 0;
		else {
			syslog(LOG_ERR, "%s: unknown domain: %s",
			    label, s);
			return (-1);
		}
	}

	v = ucl_object_lookup(elem, "address");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (nc->domain == AF_BLUETOOTH) {
			/* BD_ADDR literal or "*"; sets prefix 0 (any) or 48. */
			if (parse_bdaddr_string(s, nc->addr,
			    &nc->prefix) != 0) {
				syslog(LOG_ERR, "%s: invalid bluetooth "
				    "address: %s", label, s);
				return (-1);
			}
		} else {
			int addr_domain = 0;
			if (parse_address_string(s, nc->addr, &nc->prefix,
			    &addr_domain) != 0) {
				syslog(LOG_ERR, "%s: invalid address: %s",
				    label, s);
				return (-1);
			}
			/* Address implies domain if not explicitly set */
			if (nc->domain == AF_INET && addr_domain != 0)
				nc->domain = addr_domain;
		}
	}

	v = ucl_object_lookup(elem, "prefix");
	if (v != NULL) {
		int64_t pfx;

		if (ucl_object_type(v) != UCL_INT) {
			syslog(LOG_ERR, "%s: invalid prefix", label);
			return (-1);
		}
		pfx = ucl_object_toint(v);
		if (nc->domain == AF_BLUETOOTH) {
			/* BD_ADDR match is all-or-nothing: 0=any, 48=exact. */
			if (pfx != 0 && pfx != 48) {
				syslog(LOG_ERR, "%s: invalid bluetooth "
				    "prefix: %jd", label, (intmax_t)pfx);
				return (-1);
			}
		} else if (pfx < 0 || pfx > 128 ||
		    (nc->domain == AF_INET && pfx > 32)) {
			syslog(LOG_ERR, "%s: invalid prefix: %jd",
			    label, (intmax_t)pfx);
			return (-1);
		}
		nc->prefix = (uint8_t)pfx;
	}

	return (0);
}

void
config_init_defaults(struct authorityd_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	strlcpy(cfg->pidfile, AUTHORITYD_DEFAULT_PIDFILE,
	    sizeof(cfg->pidfile));
	strlcpy(cfg->control_socket, AUTHORITYD_CTL_SOCK,
	    sizeof(cfg->control_socket));
	cfg->control_socket_mode = AUTHORITYD_DEFAULT_CTLMODE;

	strlcpy(cfg->service_manager, AUTHORITYD_DEFAULT_SVC_MANAGER,
	    sizeof(cfg->service_manager));

	/* rc(8) administers Authority through its root-only control socket. */
	cfg->integrity_flags = CP_SF_PTRACE | CP_SF_WAIT | CP_SF_SCHED |
	    CP_SF_KTRACE | AUTHORITYD_REQUIRED_INTEGRITY_FLAGS;
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
cfg_mode(const ucl_object_t *root, struct authorityd_config *cfg)
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
			fprintf(stderr, "authorityd: empty "
			    "control_socket_mode\n");
			return;
		}
		errno = 0;
		val = strtol(ms, &endp, 0);
		if (endp == ms || *endp != '\0' || errno == ERANGE ||
		    val < 0 || val > 07777) {
			fprintf(stderr, "authorityd: invalid "
			    "control_socket_mode: %s\n", ms);
			return;
		}
	} else if (ucl_object_type(o) == UCL_INT) {
		/*
		 * Integer mode is ambiguous: 700 is decimal, not
		 * octal 0700.  Reject and require a quoted string.
		 */
		fprintf(stderr, "authorityd: control_socket_mode must be "
		    "a quoted string (e.g., \"0700\"), not an integer\n");
		return;
	} else {
		return;
	}

	if ((val & 07) != 0)
		fprintf(stderr, "authorityd: warning: control_socket_mode "
		    "%04lo is world-accessible\n", val);

	cfg->control_socket_mode = (mode_t)val;
}

static const struct {
	const char	*name;
	uint32_t	 flag;
} integrity_cfg_map[] = {
	{ "ptrace",	CP_SF_PTRACE },
	{ "signal",	CP_SF_SIGNAL },
	{ "sigkill",	CP_SF_SIGKILL },
	{ "sigcont",	CP_SF_SIGCONT },
	{ "visible",	CP_SF_VISIBLE },
	{ "wait",	CP_SF_WAIT },
	{ "sched",	CP_SF_SCHED },
	{ "core",	CP_SF_CORE },
	{ "ktrace",	CP_SF_KTRACE },
};

static void
cfg_integrity(const ucl_object_t *root, struct authorityd_config *cfg)
{
	const ucl_object_t *sec, *o;
	unsigned i;

	sec = ucl_object_lookup(root, "integrity");
	if (sec == NULL || ucl_object_type(sec) != UCL_OBJECT)
		return;

	for (i = 0; i < nitems(integrity_cfg_map); i++) {
		o = ucl_object_lookup(sec, integrity_cfg_map[i].name);
		if (o != NULL && ucl_object_type(o) == UCL_BOOLEAN) {
			if (ucl_object_toboolean(o))
				cfg->integrity_flags |=
				    integrity_cfg_map[i].flag;
			else if ((integrity_cfg_map[i].flag &
			    AUTHORITYD_REQUIRED_INTEGRITY_FLAGS) != 0) {
				fprintf(stderr, "authorityd: integrity.%s=false "
				    "ignored; ambient signal protection is mandatory\n",
				    integrity_cfg_map[i].name);
			} else
				cfg->integrity_flags &=
				    ~integrity_cfg_map[i].flag;
		}
	}
}

static void
cfg_claims(const ucl_object_t *root, struct authorityd_config *cfg)
{
	const ucl_object_t *sec, *arr, *elem;
	ucl_object_iter_t it;
	const char *s;

	sec = ucl_object_lookup(root, "claims");
	if (sec == NULL || ucl_object_type(sec) != UCL_OBJECT)
		return;

	/* claims.network — array of objects */
	arr = ucl_object_lookup(sec, "network");
	if (arr != NULL && ucl_object_type(arr) == UCL_ARRAY) {
		it = NULL;
		while ((elem = ucl_object_iterate(arr, &it, true))
		    != NULL) {
			if (ucl_object_type(elem) != UCL_OBJECT)
				continue;
			if (cfg->nclaim_net >= AUTHORITYD_MAX_NET_CLAIMS) {
				fprintf(stderr, "authorityd: too many "
				    "network claims (max %d)\n",
				    AUTHORITYD_MAX_NET_CLAIMS);
				break;
			}
			if (parse_ucl_net_claim(elem,
			    &cfg->claim_net[cfg->nclaim_net],
			    "config") == 0) {
				cfg->claim_net_source[cfg->nclaim_net] =
				    CLAIM_SOURCE_POLICY;
				cfg->nclaim_net++;
			}
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
				fprintf(stderr, "authorityd: unknown "
				    "system gate: %s\n", s);
		}
	}

	/* Record policy-originated system gates. */
	cfg->claim_system_policy = cfg->claim_system;
}

/* Maximum config file size (1 MB). */
#define	CONFIG_MAX_UCL_SIZE	(1024 * 1024)

int
config_load(struct authorityd_config *cfg, const char *path)
{
	struct ucl_parser *parser;
	const ucl_object_t *root;
	struct stat csb;

	if (stat(path, &csb) == -1) {
		if (errno == ENOENT)
			return (0);
		fprintf(stderr, "authorityd: %s: %s\n", path, strerror(errno));
		return (-1);
	}
	if (!S_ISREG(csb.st_mode)) {
		fprintf(stderr, "authorityd: %s: not a regular file\n", path);
		return (-1);
	}
	if (csb.st_size > CONFIG_MAX_UCL_SIZE) {
		fprintf(stderr, "authorityd: %s: file too large (%jd bytes)\n",
		    path, (intmax_t)csb.st_size);
		return (-1);
	}

	parser = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (parser == NULL) {
		fprintf(stderr, "authorityd: ucl_parser_new failed\n");
		return (-1);
	}

	if (!ucl_parser_add_file(parser, path)) {
		fprintf(stderr, "authorityd: %s: %s\n", path,
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
	cfg_string(root, "service_manager", cfg->service_manager,
	    sizeof(cfg->service_manager));
	cfg_mode(root, cfg);

	/* Sections */
	cfg_integrity(root, cfg);
	cfg->integrity_flags |= AUTHORITYD_REQUIRED_INTEGRITY_FLAGS;
	cfg_claims(root, cfg);

	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(parser);

	cfg->loaded_from_file = true;
	return (0);
}

void
config_log(const struct authorityd_config *cfg)
{

	if (cfg->loaded_from_file)
		syslog(LOG_INFO, "config: loaded from file");
	else
		syslog(LOG_INFO, "config: using defaults");
	syslog(LOG_INFO, "config: pidfile=%s", cfg->pidfile);
	syslog(LOG_INFO, "config: control_socket=%s mode=%04o",
	    cfg->control_socket, cfg->control_socket_mode);
	syslog(LOG_INFO, "config: integrity_flags=0x%x", cfg->integrity_flags);
	syslog(LOG_INFO, "config: claims network=%d system=0x%x",
	    cfg->nclaim_net, cfg->claim_system);
}
