/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libcapbundle — UCL parsing for .cap bundle service manifests.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include "claim_parse.h"
#include "gates.h"
#include "libcapbundle_internal.h"

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
parse_string_array_n(const ucl_object_t *obj, const char *key,
    void *dst, size_t elemsz, unsigned max, unsigned *count)
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
			strlcpy((char *)dst, s, elemsz);
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
			strlcpy((char *)dst + (*count) * elemsz, s, elemsz);
			(*count)++;
		}
	}
}

static void
parse_string_array(const ucl_object_t *obj, const char *key,
    char (*dst)[CAPBUNDLE_NAME_MAX + 1], unsigned max, unsigned *count)
{

	parse_string_array_n(obj, key, dst, CAPBUNDLE_NAME_MAX + 1, max,
	    count);
}

static int
parse_restart_policy(const ucl_object_t *obj, const char *path)
{
	const ucl_object_t *v;
	const char *s;

	v = ucl_object_lookup(obj, "restart");
	if (v == NULL || ucl_object_type(v) != UCL_STRING)
		return (CAPBUNDLE_RESTART_NEVER);

	s = ucl_object_tostring(v);
	if (strcmp(s, "always") == 0)
		return (CAPBUNDLE_RESTART_ALWAYS);
	if (strcmp(s, "never") == 0)
		return (CAPBUNDLE_RESTART_NEVER);
	if (strcmp(s, "on-failure") == 0)
		return (CAPBUNDLE_RESTART_ON_FAILURE);
	syslog(LOG_WARNING, "capbundle %s: unknown restart policy: %s",
	    path, s);
	return (CAPBUNDLE_RESTART_NEVER);
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
			    "capbundle %s: unknown system gate: %s",
			    path, gate);
		}
	}
	return (mask);
}

/*
 * Parse a single Service.ucl file within a bundle.
 */
int
capbundle_parse_service_ucl(const char *path, const char *bundle_path,
    struct capbundle_service *svc, char *bundle_id, size_t bundle_id_sz,
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
	if (ucl_sb.st_size > CAPBUNDLE_MAX_UCL_SIZE) {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: file too large (%jd bytes, max %d)",
			    path, (intmax_t)ucl_sb.st_size,
			    CAPBUNDLE_MAX_UCL_SIZE);
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

	/* Program — relative to bin/ */
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
	if (snprintf(bin_path, sizeof(bin_path), "%s/bin/%s",
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
	    CAPBUNDLE_MAX_PROVIDES, &svc->nprovides);
	if (svc->nprovides > 0)
		strlcpy(svc->label, svc->provides[0], sizeof(svc->label));
	else
		strlcpy(svc->label, program, sizeof(svc->label));

	/* Requires */
	parse_string_array(root, "requires", svc->requires,
	    CAPBUNDLE_MAX_REQUIRES, &svc->nrequires);

	/* Kernel module requirements */
	parse_string_array_n(root, "kmod_requires", svc->kmod_requires,
	    sizeof(svc->kmod_requires[0]), CAPBUNDLE_MAX_KMOD_REQUIRES,
	    &svc->nkmod_requires);

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
				while (svc->ncap_paths < CAPBUNDLE_MAX_CAP_PATHS &&
				    (elem = ucl_object_iterate(paths, &it,
				    true)) != NULL) {
					const char *p;

					if (ucl_object_type(elem) != UCL_STRING)
						continue;
					p = ucl_object_tostring(elem);
					if (p[0] != '/') {
						syslog(LOG_WARNING,
						    "capbundle %s: capability "
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
					    CAPBUNDLE_MAX_CAP_FILES &&
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
							    "capbundle %s: "
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
							    "capbundle %s: "
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
					    CAPBUNDLE_MAX_CAP_NET &&
					    (nelem = ucl_object_iterate(net,
					    &nit, true)) != NULL) {
						struct ort_net_claim *nc;
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
								    "capbundle "
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
							if (parse_net_protocol_string(
							    ps, &nc->protocol)
							    != 0) {
								syslog(
								    LOG_WARNING,
								    "capbundle "
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
								    ORT_NET_DIR_BIND;
							else if (strcmp(ps,
							    "connect") == 0)
								nc->direction =
								    ORT_NET_DIR_CONNECT;
							else if (strcmp(ps,
							    "*") == 0 ||
							    strcmp(ps, "any")
							    == 0)
								nc->direction =
								    ORT_NET_DIR_ANY;
							else {
								syslog(
								    LOG_WARNING,
								    "capbundle "
								    "%s: unknown "
								    "direction: "
								    "%s",
								    path, ps);
								continue;
							}
						}
						if (nc->direction == 0)
							nc->direction =
							    ORT_NET_DIR_BIND;

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
							    "bluetooth") == 0)
								nc->domain =
								    AF_BLUETOOTH;
							else if (strcmp(ps,
							    "*") == 0 ||
							    strcmp(ps, "any")
							    == 0)
								nc->domain = 0;
							else {
								syslog(
								    LOG_WARNING,
								    "capbundle "
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
							ps = ucl_object_tostring(
							    pv);
							if (nc->domain ==
							    AF_BLUETOOTH) {
								/* BD_ADDR or "*" */
								if (parse_bdaddr_string(
								    ps, nc->addr,
								    &nc->prefix)
								    != 0) {
									syslog(
									    LOG_WARNING,
									    "capbundle "
									    "%s: invalid"
									    " bluetooth"
									    " address: "
									    "%s", path,
									    ps);
									continue;
								}
							} else {
								int addr_domain =
								    0;

								if (parse_address_string(
								    ps, nc->addr,
								    &nc->prefix,
								    &addr_domain)
								    != 0) {
									syslog(
									    LOG_WARNING,
									    "capbundle "
									    "%s: invalid"
									    " address: "
									    "%s", path,
									    ps);
									continue;
								}
								if (nc->domain ==
								    AF_INET &&
								    addr_domain !=
								    0)
									nc->domain =
									    addr_domain;
							}
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
							if (nc->domain ==
							    AF_BLUETOOTH) {
								/* 0=any, 48=exact */
								if (pfx != 0 &&
								    pfx != 48) {
									syslog(
									    LOG_WARNING,
									    "capbundle "
									    "%s: invalid"
									    " bluetooth"
									    " prefix: "
									    "%jd", path,
									    (intmax_t)pfx);
									continue;
								}
							} else if (pfx < 0 ||
							    pfx > 128 ||
							    (nc->domain ==
							    AF_INET &&
							    pfx > 32)) {
								syslog(
								    LOG_WARNING,
								    "capbundle "
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
					    CAPBUNDLE_MAX_CAP_JAIL &&
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
								    "capbundle "
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
								    "capbundle "
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
							    "capbundle %s: "
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
