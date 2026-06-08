/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libappbundle — parse and validate 5BSD .app bundles.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include <dev/cap_rt/cap_rt_isolation_proto.h>

#include "libappbundle.h"
#include "serviced_manifest.h"
#include "claim_parse.h"
#include "gates.h"

/* Limits matching serviced.h */
#define	APPBUNDLE_MAX_CAP_PATHS		16
#define	APPBUNDLE_MAX_CAP_FILES		16
#define	APPBUNDLE_MAX_CAP_NET		16
#define	APPBUNDLE_MAX_CAP_JAIL		16

/* Internal service representation. */
struct appbundle_service {
	char	program[PATH_MAX];	/* absolute resolved path */
	char	label[APPBUNDLE_NAME_MAX + 1];
	char	provides[APPBUNDLE_MAX_PROVIDES][APPBUNDLE_NAME_MAX + 1];
	unsigned nprovides;
	char	requires[APPBUNDLE_MAX_REQUIRES][APPBUNDLE_NAME_MAX + 1];
	unsigned nrequires;
	bool	on_demand;
	int	restart;
	uint32_t cap_system;		/* SYS_GATE_* bitmask */

	/* Path capabilities */
	char	cap_paths[APPBUNDLE_MAX_CAP_PATHS][PATH_MAX];
	unsigned ncap_paths;

	/* File capabilities (fine-grained, with actions) */
	struct {
		char	path[PATH_MAX];
		uint64_t actions;	/* FI_FS_* mask */
	} cap_files[APPBUNDLE_MAX_CAP_FILES];
	unsigned ncap_files;

	/* Network capabilities (full: domain, address, prefix, port range) */
	struct serviced_net_claim cap_net[APPBUNDLE_MAX_CAP_NET];
	unsigned ncap_net;

	/* Jail capabilities */
	struct serviced_jail_claim cap_jail[APPBUNDLE_MAX_CAP_JAIL];
	unsigned ncap_jail;

	/* User/group for privilege drop */
	char	user[64];
	char	group[64];

	/* Stop timeout */
	int	stop_timeout;
	unsigned max_failures;
};

/* Internal bundle representation. */
struct appbundle {
	char	path[PATH_MAX];		/* bundle directory */
	char	name[256];		/* basename of path (e.g. "Mail.app") */
	char	bundle_id[APPBUNDLE_ID_MAX];
	char	version[APPBUNDLE_VERSION_MAX];
	char	author[APPBUNDLE_AUTHOR_MAX];
	struct appbundle_service services[APPBUNDLE_MAX_SERVICES];
	unsigned nservices;
};

/* --- UCL parsing helpers --- */

static void
parse_string_field(const ucl_object_t *obj, const char *key,
    char *dst, size_t dstsz)
{
	const ucl_object_t *v;

	v = ucl_object_lookup(obj, key);
	if (v != NULL && ucl_object_type(v) == UCL_STRING)
		strlcpy(dst, ucl_object_tostring(v), dstsz);
}

static void
parse_string_array(const ucl_object_t *obj, const char *key,
    char (*dst)[APPBUNDLE_NAME_MAX + 1], unsigned max, unsigned *count)
{
	const ucl_object_t *arr, *elem;
	ucl_object_iter_t it;

	*count = 0;
	arr = ucl_object_lookup(obj, key);
	if (arr == NULL)
		return;

	if (ucl_object_type(arr) == UCL_STRING) {
		/* Single string, not an array. */
		const char *s = ucl_object_tostring(arr);
		if (s[0] != '\0') {
			strlcpy(dst[0], s, APPBUNDLE_NAME_MAX + 1);
			*count = 1;
		}
		return;
	}

	if (ucl_object_type(arr) != UCL_ARRAY)
		return;

	it = NULL;
	while (*count < max &&
	    (elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(elem) == UCL_STRING) {
			const char *s = ucl_object_tostring(elem);
			if (s[0] == '\0')
				continue;
			strlcpy(dst[*count], s, APPBUNDLE_NAME_MAX + 1);
			(*count)++;
		}
	}
}

static int
manifest_copy(const char *src, char *dst, size_t dstsz)
{

	return (strlcpy(dst, src, dstsz) < dstsz ? 0 : -1);
}

static int
parse_restart_policy(const ucl_object_t *obj, const char *path)
{
	const ucl_object_t *v;
	const char *s;

	v = ucl_object_lookup(obj, "restart");
	if (v == NULL || ucl_object_type(v) != UCL_STRING)
		return (APPBUNDLE_RESTART_NEVER);

	s = ucl_object_tostring(v);
	if (strcmp(s, "always") == 0)
		return (APPBUNDLE_RESTART_ALWAYS);
	if (strcmp(s, "never") == 0)
		return (APPBUNDLE_RESTART_NEVER);
	if (strcmp(s, "on-failure") == 0)
		return (APPBUNDLE_RESTART_ON_FAILURE);
	syslog(LOG_WARNING, "appbundle %s: unknown restart policy: %s",
	    path, s);
	return (APPBUNDLE_RESTART_NEVER);
}

static uint32_t
parse_cap_system(const ucl_object_t *obj, const char *path)
{
	const ucl_object_t *caps, *sys, *elem;
	ucl_object_iter_t it;
	uint32_t mask;
	unsigned gi;
	bool found;

	mask = 0;
	caps = ucl_object_lookup(obj, "capabilities");
	if (caps == NULL)
		return (0);

	sys = ucl_object_lookup(caps, "system");
	if (sys == NULL)
		return (0);

	it = NULL;
	while ((elem = ucl_object_iterate(sys, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_STRING)
			continue;
		const char *gate = ucl_object_tostring(elem);
		found = false;
		for (gi = 0; gi < nitems(gate_names); gi++) {
			if (strcmp(gate, gate_names[gi].name) == 0) {
				mask |= gate_names[gi].gate;
				found = true;
				break;
			}
		}
		if (!found) {
			syslog(LOG_WARNING,
			    "appbundle %s: unknown system gate: %s",
			    path, gate);
		}
	}
	return (mask);
}

/*
 * Parse a single Service.ucl file within a bundle.
 */
/* Maximum Service.ucl file size (1 MB).  Protects against OOM. */
#define	APPBUNDLE_MAX_UCL_SIZE	(1024 * 1024)

static int
parse_service_ucl(const char *path, const char *bundle_path,
    struct appbundle_service *svc, char *bundle_id, size_t bundle_id_sz,
    char *version, size_t version_sz, char *author, size_t author_sz,
    char *errbuf, size_t errlen)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *v;
	const char *program;
	char bin_path[PATH_MAX];
	struct stat ucl_sb;

	memset(svc, 0, sizeof(*svc));

	/* Reject unreasonably large files before parsing. */
	if (stat(path, &ucl_sb) == -1) {
		if (errbuf)
			snprintf(errbuf, errlen, "%s: %s", path,
			    strerror(errno));
		return (-1);
	}
	if (!S_ISREG(ucl_sb.st_mode)) {
		if (errbuf)
			snprintf(errbuf, errlen, "%s: not a regular file",
			    path);
		return (-1);
	}
	if (ucl_sb.st_size > APPBUNDLE_MAX_UCL_SIZE) {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: file too large (%jd bytes, max %d)",
			    path, (intmax_t)ucl_sb.st_size,
			    APPBUNDLE_MAX_UCL_SIZE);
		return (-1);
	}

	parser = ucl_parser_new(0);
	if (parser == NULL) {
		if (errbuf)
			snprintf(errbuf, errlen, "ucl_parser_new failed");
		return (-1);
	}

	if (!ucl_parser_add_file(parser, path)) {
		if (errbuf)
			snprintf(errbuf, errlen, "%s: %s", path,
			    ucl_parser_get_error(parser));
		ucl_parser_free(parser);
		return (-1);
	}

	root = ucl_parser_get_object(parser);
	ucl_parser_free(parser);
	if (root == NULL) {
		if (errbuf)
			snprintf(errbuf, errlen, "%s: empty document", path);
		return (-1);
	}

	/* Bundle metadata (extracted from first service parsed). */
	parse_string_field(root, "bundle_id", bundle_id, bundle_id_sz);
	parse_string_field(root, "version", version, version_sz);
	parse_string_field(root, "author", author, author_sz);

	/* Program — relative to Contents/bin/ */
	v = ucl_object_lookup(root, "program");
	if (v == NULL || ucl_object_type(v) != UCL_STRING) {
		if (errbuf)
			snprintf(errbuf, errlen, "%s: missing 'program' field",
			    path);
		ucl_object_unref(root);
		return (-1);
	}
	program = ucl_object_tostring(v);
	/* Reject path traversal and absolute paths in program name. */
	if (program[0] == '/' || program[0] == '\0' ||
	    strstr(program, "..") != NULL) {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: invalid program name: %s", path, program);
		ucl_object_unref(root);
		return (-1);
	}
	if (snprintf(bin_path, sizeof(bin_path), "%s/Contents/bin/%s",
	    bundle_path, program) >= (int)sizeof(bin_path)) {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: resolved program path too long", path);
		ucl_object_unref(root);
		return (-1);
	}
	strlcpy(svc->program, bin_path, sizeof(svc->program));

	/* Label — use first provides name, or derive from program. */
	parse_string_array(root, "provides", svc->provides,
	    APPBUNDLE_MAX_PROVIDES, &svc->nprovides);
	if (svc->nprovides > 0)
		strlcpy(svc->label, svc->provides[0], sizeof(svc->label));
	else
		strlcpy(svc->label, program, sizeof(svc->label));

	/* Requires */
	parse_string_array(root, "requires", svc->requires,
	    APPBUNDLE_MAX_REQUIRES, &svc->nrequires);

	/* On-demand */
	v = ucl_object_lookup(root, "on_demand");
	if (v != NULL && ucl_object_type(v) == UCL_BOOLEAN)
		svc->on_demand = ucl_object_toboolean(v);

	/* Restart policy */
	svc->restart = parse_restart_policy(root, path);

	/* System capabilities */
	svc->cap_system = parse_cap_system(root, path);

	/* Path capabilities */
	{
		const ucl_object_t *caps, *paths, *elem;
		ucl_object_iter_t it;

		caps = ucl_object_lookup(root, "capabilities");
		if (caps != NULL) {
			paths = ucl_object_lookup(caps, "paths");
			if (paths != NULL) {
				it = NULL;
				while (svc->ncap_paths < APPBUNDLE_MAX_CAP_PATHS &&
				    (elem = ucl_object_iterate(paths, &it,
				    true)) != NULL) {
					const char *p;

					if (ucl_object_type(elem) != UCL_STRING)
						continue;
					p = ucl_object_tostring(elem);
					if (p[0] != '/') {
						syslog(LOG_WARNING,
						    "appbundle %s: capability "
						    "path must be absolute: %s",
						    path, p);
						continue;
					}
					strlcpy(svc->cap_paths[svc->ncap_paths++],
					    p, PATH_MAX);
				}
			}

			/* File capabilities (fine-grained with actions) */
			{
				const ucl_object_t *files, *felem;
				ucl_object_iter_t fit;

				files = ucl_object_lookup(caps, "files");
				if (files != NULL) {
					fit = NULL;
					while (svc->ncap_files <
					    APPBUNDLE_MAX_CAP_FILES &&
					    (felem = ucl_object_iterate(files,
					    &fit, true)) != NULL) {
						const ucl_object_t *fv;
						const char *fp;

						if (ucl_object_type(felem) !=
						    UCL_OBJECT)
							continue;
						fv = ucl_object_lookup(felem,
						    "path");
						if (fv == NULL ||
						    ucl_object_type(fv) !=
						    UCL_STRING)
							continue;
						fp = ucl_object_tostring(fv);
						if (fp[0] != '/') {
							syslog(LOG_WARNING,
							    "appbundle %s: "
							    "file cap path "
							    "must be absolute:"
							    " %s", path, fp);
							continue;
						}
						strlcpy(svc->cap_files[
						    svc->ncap_files].path,
						    fp, PATH_MAX);
						fv = ucl_object_lookup(felem,
						    "actions");
						if (parse_file_actions(fv,
						    &svc->cap_files[
						    svc->ncap_files].actions)
						    != 0) {
							syslog(LOG_WARNING,
							    "appbundle %s: "
							    "invalid file "
							    "actions", path);
							continue;
						}
						svc->ncap_files++;
					}
				}
			}

			/* Network capabilities — full parsing via
			 * parse_ucl_net_claim-style logic matching manifest.c */
			{
				const ucl_object_t *net, *nelem;
				ucl_object_iter_t nit;

				net = ucl_object_lookup(caps, "network");
				if (net != NULL) {
					nit = NULL;
					while (svc->ncap_net <
					    APPBUNDLE_MAX_CAP_NET &&
					    (nelem = ucl_object_iterate(net,
					    &nit, true)) != NULL) {
						struct serviced_net_claim *nc;
						const ucl_object_t *pv;
						const char *ps;

						if (ucl_object_type(nelem) !=
						    UCL_OBJECT)
							continue;

						nc = &svc->cap_net[
						    svc->ncap_net];
						memset(nc, 0, sizeof(*nc));
						nc->port_min = 0;
						nc->port_max = UINT16_MAX;
						nc->domain = AF_INET;

						/* port / ports */
						pv = ucl_object_lookup(nelem,
						    "port");
						if (pv == NULL)
							pv = ucl_object_lookup(
							    nelem, "ports");
						if (pv != NULL) {
							if (parse_port_range_obj(
							    pv, &nc->port_min,
							    &nc->port_max)
							    != 0) {
								syslog(
								    LOG_WARNING,
								    "appbundle "
								    "%s: invalid"
								    " port range",
								    path);
								continue;
							}
						}

						/* protocol */
						pv = ucl_object_lookup(nelem,
						    "protocol");
						if (pv != NULL &&
						    ucl_object_type(pv) ==
						    UCL_STRING) {
							ps = ucl_object_tostring(pv);
							if (strcmp(ps, "tcp")
							    == 0)
								nc->protocol =
								    IPPROTO_TCP;
							else if (strcmp(ps,
							    "udp") == 0)
								nc->protocol =
								    IPPROTO_UDP;
							else if (strcmp(ps,
							    "*") == 0 ||
							    strcmp(ps, "any")
							    == 0)
								nc->protocol =
								    0;
							else {
								syslog(
								    LOG_WARNING,
								    "appbundle "
								    "%s: unknown "
								    "protocol: "
								    "%s",
								    path, ps);
								continue;
							}
						}

						/* direction */
						pv = ucl_object_lookup(nelem,
						    "direction");
						if (pv != NULL &&
						    ucl_object_type(pv) ==
						    UCL_STRING) {
							ps = ucl_object_tostring(pv);
							if (strcmp(ps, "bind")
							    == 0)
								nc->direction =
								    SERVICED_NET_DIR_BIND;
							else if (strcmp(ps,
							    "connect") == 0)
								nc->direction =
								    SERVICED_NET_DIR_CONNECT;
							else if (strcmp(ps,
							    "*") == 0 ||
							    strcmp(ps, "any")
							    == 0)
								nc->direction =
								    SERVICED_NET_DIR_ANY;
							else {
								syslog(
								    LOG_WARNING,
								    "appbundle "
								    "%s: unknown "
								    "direction: "
								    "%s",
								    path, ps);
								continue;
							}
						}
						if (nc->direction == 0)
							nc->direction =
							    SERVICED_NET_DIR_BIND;

						/* domain */
						pv = ucl_object_lookup(nelem,
						    "domain");
						if (pv != NULL &&
						    ucl_object_type(pv) ==
						    UCL_STRING) {
							ps = ucl_object_tostring(pv);
							if (strcmp(ps, "inet")
							    == 0)
								nc->domain =
								    AF_INET;
							else if (strcmp(ps,
							    "inet6") == 0)
								nc->domain =
								    AF_INET6;
							else if (strcmp(ps,
							    "*") == 0 ||
							    strcmp(ps, "any")
							    == 0)
								nc->domain = 0;
							else {
								syslog(
								    LOG_WARNING,
								    "appbundle "
								    "%s: unknown "
								    "domain: %s",
								    path, ps);
								continue;
							}
						}

						/* address */
						pv = ucl_object_lookup(nelem,
						    "address");
						if (pv != NULL &&
						    ucl_object_type(pv) ==
						    UCL_STRING) {
							int addr_domain = 0;

							if (parse_address_string(
							    ucl_object_tostring(
							    pv), nc->addr,
							    &nc->prefix,
							    &addr_domain)
							    != 0) {
								syslog(
								    LOG_WARNING,
								    "appbundle "
								    "%s: invalid"
								    " address: "
								    "%s", path,
								    ucl_object_tostring(pv));
								continue;
							}
							if (nc->domain ==
							    AF_INET &&
							    addr_domain != 0)
								nc->domain =
								    addr_domain;
						}

						/* explicit prefix override */
						pv = ucl_object_lookup(nelem,
						    "prefix");
						if (pv != NULL &&
						    ucl_object_type(pv) ==
						    UCL_INT) {
							int64_t pfx =
							    ucl_object_toint(
							    pv);
							if (pfx < 0 ||
							    pfx > 128 ||
							    (nc->domain ==
							    AF_INET &&
							    pfx > 32)) {
								syslog(
								    LOG_WARNING,
								    "appbundle "
								    "%s: invalid"
								    " prefix: "
								    "%jd", path,
								    (intmax_t)pfx);
								continue;
							}
							nc->prefix =
							    (uint8_t)pfx;
						}

						svc->ncap_net++;
					}
				}
			}

			/* Jail capabilities — full parsing matching
			 * manifest.c parse_ucl_jail_claim() */
			{
				const ucl_object_t *jails, *jelem;
				ucl_object_iter_t jit;

				jails = ucl_object_lookup(caps, "jails");
				if (jails != NULL) {
					jit = NULL;
					while (svc->ncap_jail <
					    APPBUNDLE_MAX_CAP_JAIL &&
					    (jelem = ucl_object_iterate(jails,
					    &jit, true)) != NULL) {
						struct serviced_jail_claim *jc;
						const ucl_object_t *jv;
						int64_t jid;

						jc = &svc->cap_jail[
						    svc->ncap_jail];
						memset(jc, 0, sizeof(*jc));
						jc->actions = FI_JAIL_ALL;

						switch (ucl_object_type(jelem)){
						case UCL_INT:
							jid = ucl_object_toint(
							    jelem);
							if (jid <= 0 ||
							    jid > INT32_MAX) {
								syslog(
								    LOG_WARNING,
								    "appbundle "
								    "%s: invalid"
								    " jail jid",
								    path);
								continue;
							}
							jc->jid =
							    (int32_t)jid;
							svc->ncap_jail++;
							continue;
						case UCL_STRING:
							if (strlcpy(jc->name,
							    ucl_object_tostring(
							    jelem),
							    sizeof(jc->name))
							    >= sizeof(
							    jc->name)) {
								syslog(
								    LOG_WARNING,
								    "appbundle "
								    "%s: jail "
								    "name too "
								    "long", path);
								continue;
							}
							if (jc->name[0] ==
							    '\0')
								continue;
							svc->ncap_jail++;
							continue;
						case UCL_OBJECT:
							break;
						default:
							continue;
						}

						/* Object form */
						jv = ucl_object_lookup(jelem,
						    "jid");
						if (jv != NULL) {
							if (ucl_object_type(jv)
							    != UCL_INT)
								continue;
							jid =
							    ucl_object_toint(
							    jv);
							if (jid <= 0 ||
							    jid > INT32_MAX)
								continue;
							jc->jid =
							    (int32_t)jid;
						}
						jv = ucl_object_lookup(jelem,
						    "name");
						if (jv != NULL &&
						    ucl_object_type(jv) ==
						    UCL_STRING) {
							if (strlcpy(jc->name,
							    ucl_object_tostring(
							    jv),
							    sizeof(jc->name))
							    >= sizeof(
							    jc->name))
								continue;
						}
						jv = ucl_object_lookup(jelem,
						    "actions");
						if (parse_jail_actions(jv,
						    &jc->actions) != 0) {
							syslog(LOG_WARNING,
							    "appbundle %s: "
							    "invalid jail "
							    "actions", path);
							continue;
						}
						/* Must have jid or name */
						if (jc->jid == 0 &&
						    jc->name[0] == '\0')
							continue;
						svc->ncap_jail++;
					}
				}
			}
		}
	}

	/* User/group */
	v = ucl_object_lookup(root, "user");
	if (v != NULL && ucl_object_type(v) == UCL_STRING &&
	    strlcpy(svc->user, ucl_object_tostring(v),
	    sizeof(svc->user)) >= sizeof(svc->user)) {
		if (errbuf)
			snprintf(errbuf, errlen, "%s: user too long", path);
		ucl_object_unref(root);
		return (-1);
	}
	v = ucl_object_lookup(root, "group");
	if (v != NULL && ucl_object_type(v) == UCL_STRING &&
	    strlcpy(svc->group, ucl_object_tostring(v),
	    sizeof(svc->group)) >= sizeof(svc->group)) {
		if (errbuf)
			snprintf(errbuf, errlen, "%s: group too long", path);
		ucl_object_unref(root);
		return (-1);
	}

	/* Stop timeout / max failures — clamp to same ranges as manifest.c */
	v = ucl_object_lookup(root, "stop_timeout");
	if (v != NULL && ucl_object_type(v) == UCL_INT) {
		int64_t t = ucl_object_toint(v);
		if (t < 1)
			t = 1;
		else if (t > 300)
			t = 300;
		svc->stop_timeout = (int)t;
	} else
		svc->stop_timeout = 5;
	v = ucl_object_lookup(root, "max_failures");
	if (v != NULL && ucl_object_type(v) == UCL_INT) {
		int64_t mf = ucl_object_toint(v);
		if (mf < 1)
			mf = 1;
		else if (mf > 100)
			mf = 100;
		svc->max_failures = (unsigned)mf;
	} else
		svc->max_failures = 10;

	ucl_object_unref(root);
	return (0);
}

/* --- Public API --- */

int
appbundle_open(const char *path, struct appbundle **bp,
    char *errbuf, size_t errlen)
{
	struct appbundle *b;
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

	/* Check Contents/5BSD/Services/ exists. */
	snprintf(services_dir, sizeof(services_dir),
	    "%s/Contents/5BSD/Services", b->path);
	d = opendir(services_dir);
	if (d == NULL) {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: Contents/5BSD/Services/ not found", b->name);
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
			if (b->nservices >= APPBUNDLE_MAX_SERVICES)
				break;

			snprintf(svc_path, sizeof(svc_path), "%s/%s",
			    services_dir, de->d_name);

			if (parse_service_ucl(svc_path, b->path,
			    &b->services[b->nservices],
			    b->bundle_id, sizeof(b->bundle_id),
			    b->version, sizeof(b->version),
			    b->author, sizeof(b->author),
			    fail_errbuf,
			    sizeof(fail_errbuf)) == 0) {
				b->nservices++;
			} else {
				syslog(LOG_WARNING,
				    "appbundle %s: skipping %s: %s",
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
			appbundle_close(b);
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
appbundle_close(struct appbundle *b)
{

	free(b);
}

const char *
appbundle_id(const struct appbundle *b)
{

	return (b->bundle_id);
}

const char *
appbundle_version(const struct appbundle *b)
{

	return (b->version);
}

const char *
appbundle_author(const struct appbundle *b)
{

	return (b->author);
}

const char *
appbundle_path(const struct appbundle *b)
{

	return (b->path);
}

const char *
appbundle_name(const struct appbundle *b)
{

	return (b->name);
}

unsigned
appbundle_nservices(const struct appbundle *b)
{

	return (b->nservices);
}

struct appbundle_service *
appbundle_service(const struct appbundle *b, unsigned idx)
{

	if (idx >= b->nservices)
		return (NULL);
	/* Safe: callers receive const pointer via the public API. */
	return (__DECONST(struct appbundle_service *, &b->services[idx]));
}

const char *
appbundle_svc_program(const struct appbundle_service *s)
{

	return (s->program);
}

const char *
appbundle_svc_label(const struct appbundle_service *s)
{

	return (s->label);
}

unsigned
appbundle_svc_nprovides(const struct appbundle_service *s)
{

	return (s->nprovides);
}

const char *
appbundle_svc_provides(const struct appbundle_service *s, unsigned idx)
{

	if (idx >= s->nprovides)
		return (NULL);
	return (s->provides[idx]);
}

unsigned
appbundle_svc_nrequires(const struct appbundle_service *s)
{

	return (s->nrequires);
}

const char *
appbundle_svc_requires(const struct appbundle_service *s, unsigned idx)
{

	if (idx >= s->nrequires)
		return (NULL);
	return (s->requires[idx]);
}

bool
appbundle_svc_on_demand(const struct appbundle_service *s)
{

	return (s->on_demand);
}

int
appbundle_svc_restart(const struct appbundle_service *s)
{

	return (s->restart);
}

uint32_t
appbundle_svc_cap_system(const struct appbundle_service *s)
{

	return (s->cap_system);
}

unsigned
appbundle_svc_ncap_paths(const struct appbundle_service *s)
{

	return (s->ncap_paths);
}

const char *
appbundle_svc_cap_path(const struct appbundle_service *s, unsigned idx)
{

	if (idx >= s->ncap_paths)
		return (NULL);
	return (s->cap_paths[idx]);
}

unsigned
appbundle_svc_ncap_net(const struct appbundle_service *s)
{

	return (s->ncap_net);
}

unsigned
appbundle_svc_ncap_jail(const struct appbundle_service *s)
{

	return (s->ncap_jail);
}

/*
 * Fill a svc_manifest from a bundle service.
 * This is the canonical way to populate all fields including capabilities.
 */
int
appbundle_svc_fill_manifest(const struct appbundle_service *s,
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
	for (i = 0; i < s->nprovides && i < APPBUNDLE_MAX_PROVIDES; i++) {
		if (manifest_copy(s->provides[i], m->provides[i],
		    sizeof(m->provides[i])) == -1)
			return (-1);
	}

	m->nrequires = s->nrequires;
	for (i = 0; i < s->nrequires && i < APPBUNDLE_MAX_REQUIRES; i++) {
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

	return (0);
}

/* --- Verification --- */

int
appbundle_verify(const struct appbundle *b, char *errbuf, size_t errlen)
{
	unsigned i, j, k;
	struct stat sb;

	if (b->bundle_id[0] == '\0') {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: no bundle_id in any service", b->name);
		return (-1);
	}

	for (i = 0; i < b->nservices; i++) {
		const struct appbundle_service *s = &b->services[i];

		/* Binary must exist and be executable. */
		if (stat(s->program, &sb) == -1) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: binary not found: %s",
				    b->name, s->program);
			return (-1);
		}
		if (!S_ISREG(sb.st_mode) || !(sb.st_mode & S_IXUSR)) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: not executable: %s",
				    b->name, s->program);
			return (-1);
		}

		/* Must provide at least one name. */
		if (s->nprovides == 0) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: service '%s' has no provides",
				    b->name, s->label);
			return (-1);
		}
		if (strlen(s->label) >= SERVICED_LABEL_MAX) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: service label too long: %s",
				    b->name, s->label);
			return (-1);
		}
		for (j = 0; j < s->nprovides; j++) {
			if (strlen(s->provides[j]) >= SERVICED_LABEL_MAX) {
				if (errbuf)
					snprintf(errbuf, errlen,
					    "%s: provides name too long: %s",
					    b->name, s->provides[j]);
				return (-1);
			}
		}
		for (j = 0; j < s->nrequires; j++) {
			if (strlen(s->requires[j]) >= SERVICED_LABEL_MAX) {
				if (errbuf)
					snprintf(errbuf, errlen,
					    "%s: requires name too long: %s",
					    b->name, s->requires[j]);
				return (-1);
			}
		}

		/* Check for duplicate provides within the bundle. */
		for (j = 0; j < i; j++) {
			const struct appbundle_service *prev = &b->services[j];
			for (k = 0; k < s->nprovides; k++) {
				unsigned m;
				for (m = 0; m < prev->nprovides; m++) {
					if (strcmp(s->provides[k],
					    prev->provides[m]) == 0) {
						if (errbuf)
							snprintf(errbuf, errlen,
							    "%s: duplicate provides '%s'",
							    b->name, s->provides[k]);
						return (-1);
					}
				}
			}
		}

		/* Intra-bundle cycle: service requires its own provides. */
		for (j = 0; j < s->nrequires; j++) {
			for (k = 0; k < s->nprovides; k++) {
				if (strcmp(s->requires[j],
				    s->provides[k]) == 0) {
					if (errbuf)
						snprintf(errbuf, errlen,
						    "%s: '%s' requires itself",
						    b->name, s->label);
					return (-1);
				}
			}
		}
	}

	return (0);
}

/* --- Cycle Detection (Kahn's Algorithm) --- */

int
appbundle_check_cycles(struct appbundle **bundles, unsigned nbundles,
    char *errbuf, size_t errlen)
{
	/*
	 * Build adjacency from provides → requires.
	 * Each provides name is a node.  An edge exists from node A to
	 * node B if the service providing B requires A.
	 *
	 * Use a simple flat array of all service nodes.
	 */
	struct node {
		const char *name;		/* first provides name = identity */
		unsigned in_degree;
		unsigned deps[APPBUNDLE_MAX_REQUIRES];
		unsigned ndeps;
	};
	struct node *nodes;
	unsigned nnodes, cap;
	unsigned i, j, k, bi, si;
	unsigned *queue, qhead, qtail, processed;

	/* Count total services. */
	cap = 0;
	for (bi = 0; bi < nbundles; bi++)
		cap += bundles[bi]->nservices;

	if (cap == 0)
		return (0);

	nodes = calloc(cap, sizeof(*nodes));
	queue = calloc(cap, sizeof(*queue));
	if (nodes == NULL || queue == NULL) {
		free(nodes);
		free(queue);
		if (errbuf)
			snprintf(errbuf, errlen, "out of memory");
		return (-1);
	}

	/* Populate nodes. */
	nnodes = 0;
	for (bi = 0; bi < nbundles; bi++) {
		for (si = 0; si < bundles[bi]->nservices; si++) {
			nodes[nnodes].name = bundles[bi]->services[si].label;
			nodes[nnodes].in_degree = 0;
			nodes[nnodes].ndeps = 0;
			nnodes++;
		}
	}

	/*
	 * Build edges: for each service's requires[], find the node that
	 * provides that name, and add an edge (provider → this service).
	 */
	nnodes = 0;
	for (bi = 0; bi < nbundles; bi++) {
		for (si = 0; si < bundles[bi]->nservices; si++) {
			const struct appbundle_service *svc =
			    &bundles[bi]->services[si];

			for (j = 0; j < svc->nrequires; j++) {
				/* Find provider of this requirement. */
				unsigned provider_idx = (unsigned)-1;
				unsigned ni = 0;

				for (unsigned b2 = 0; b2 < nbundles; b2++) {
					for (unsigned s2 = 0;
					    s2 < bundles[b2]->nservices; s2++) {
						const struct appbundle_service *p =
						    &bundles[b2]->services[s2];
						for (k = 0; k < p->nprovides; k++) {
							if (strcmp(p->provides[k],
							    svc->requires[j]) == 0) {
								provider_idx = ni;
								goto found;
							}
						}
						ni++;
					}
				}
found:
				if (provider_idx != (unsigned)-1) {
					/* Edge: provider → this node */
					if (nodes[provider_idx].ndeps <
					    APPBUNDLE_MAX_REQUIRES) {
						nodes[provider_idx].deps[
						    nodes[provider_idx].ndeps++] =
						    nnodes;
					}
					nodes[nnodes].in_degree++;
				}
			}
			nnodes++;
		}
	}

	/* Kahn's algorithm: process nodes with in_degree == 0. */
	qhead = qtail = 0;
	for (i = 0; i < nnodes; i++) {
		if (nodes[i].in_degree == 0)
			queue[qtail++] = i;
	}

	processed = 0;
	while (qhead < qtail) {
		unsigned cur = queue[qhead++];
		processed++;
		for (j = 0; j < nodes[cur].ndeps; j++) {
			unsigned dep = nodes[cur].deps[j];
			nodes[dep].in_degree--;
			if (nodes[dep].in_degree == 0)
				queue[qtail++] = dep;
		}
	}

	free(queue);

	if (processed < nnodes) {
		/* Cycle detected — find a participating node. */
		if (errbuf) {
			for (i = 0; i < nnodes; i++) {
				if (nodes[i].in_degree > 0) {
					snprintf(errbuf, errlen,
					    "circular dependency involving '%s'",
					    nodes[i].name);
					break;
				}
			}
		}
		free(nodes);
		return (-1);
	}

	free(nodes);
	return (0);
}

/* --- Directory Scanning --- */

int
appbundle_scan_dir(const char *dirpath, appbundle_scan_cb cb, void *ctx)
{
	DIR *d;
	struct dirent *de;
	char path[PATH_MAX];
	struct appbundle *b;
	char errbuf[256];
	size_t len;
	int ret;

	d = opendir(dirpath);
	if (d == NULL)
		return (-1);

	while ((de = readdir(d)) != NULL) {
		len = strlen(de->d_name);
		if (len < 5 || strcmp(de->d_name + len - 4, ".app") != 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);

		if (appbundle_open(path, &b, errbuf, sizeof(errbuf)) == -1)
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
