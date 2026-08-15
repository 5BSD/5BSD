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
#include <sys/vsock.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include "claim_parse.h"
#include "gates.h"
#include "libcapbundle_internal.h"

static bool
key_in(const char *key, const char *const *allowed, size_t nallowed)
{
	size_t i;

	for (i = 0; i < nallowed; i++)
		if (strcmp(key, allowed[i]) == 0)
			return (true);
	return (false);
}

static int
parse_vsock_ports(const ucl_object_t *v, uint32_t *minp, uint32_t *maxp)
{
	const char *s;
	char *end;
	uint64_t lo, hi;

	if (v == NULL || (ucl_object_type(v) == UCL_STRING &&
	    strcmp(ucl_object_tostring(v), "*") == 0)) {
		*minp = 0;
		*maxp = UINT32_MAX;
		return (0);
	}
	if (ucl_object_type(v) == UCL_INT) {
		int64_t n = ucl_object_toint(v);
		if (n < 0 || (uint64_t)n > UINT32_MAX)
			return (-1);
		*minp = *maxp = (uint32_t)n;
		return (0);
	}
	if (ucl_object_type(v) != UCL_STRING)
		return (-1);
	s = ucl_object_tostring(v);
	errno = 0;
	lo = strtoull(s, &end, 10);
	if (errno != 0 || end == s || *end != '-' || lo > UINT32_MAX)
		return (-1);
	s = end + 1;
	hi = strtoull(s, &end, 10);
	if (errno != 0 || *end != '\0' || hi > UINT32_MAX || lo > hi)
		return (-1);
	*minp = (uint32_t)lo;
	*maxp = (uint32_t)hi;
	return (0);
}

static int
validate_keys(const ucl_object_t *obj, const char *where,
    const char *const *allowed, size_t nallowed, char *errbuf, size_t errlen)
{
	const ucl_object_t *v;
	ucl_object_iter_t it;
	const char *key;

	if (obj == NULL || ucl_object_type(obj) != UCL_OBJECT) {
		snprintf(errbuf, errlen, "%s must be an object", where);
		return (-1);
	}
	it = NULL;
	while ((v = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(v);
		if (key == NULL || !key_in(key, allowed, nallowed)) {
			snprintf(errbuf, errlen, "%s: unknown key '%s'", where,
			    key != NULL ? key : "");
			return (-1);
		}
	}
	return (0);
}

static int
validate_string_list(const ucl_object_t *root, const char *key, unsigned max,
    size_t maxlen, char *errbuf, size_t errlen)
{
	const ucl_object_t *arr, *v;
	ucl_object_iter_t it;
	unsigned n;

	arr = ucl_object_lookup(root, key);
	if (arr == NULL)
		return (0);
	if (ucl_object_type(arr) == UCL_STRING) {
		if (ucl_object_tostring(arr)[0] == '\0' ||
		    strlen(ucl_object_tostring(arr)) >= maxlen) {
			snprintf(errbuf, errlen, "%s contains an invalid string", key);
			return (-1);
		}
		return (0);
	}
	if (ucl_object_type(arr) != UCL_ARRAY) {
		snprintf(errbuf, errlen, "%s must be a string or array", key);
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (++n > max) {
			snprintf(errbuf, errlen, "%s has more than %u entries", key,
			    max);
			return (-1);
		}
		if (ucl_object_type(v) != UCL_STRING ||
		    ucl_object_tostring(v)[0] == '\0' ||
		    strlen(ucl_object_tostring(v)) >= maxlen) {
			snprintf(errbuf, errlen, "%s contains an invalid string", key);
			return (-1);
		}
	}
	return (0);
}

static int
validate_manifest_schema(const ucl_object_t *root, char *errbuf, size_t errlen)
{
	static const char *const top[] = { "schema", "schema_version",
	    "bundle_id", "version", "author",
	    "program", "provides", "kmod_requires",
	    "restart", "capabilities", "user", "group", "stop_timeout",
	    "max_failures", "arguments", "environment",
	    "components", "jail" };
	static const char *const capkeys[] = { "paths", "files", "network",
	    "jails", "vsock", "services", "system", "storage" };
	static const char *const storagekeys[] = { "name", "flavor", "rights",
	    "lifetime" };
	static const char *const service_names[] = { "mount", "node",
	    "accounting", "identity" };
	static const char *const filekeys[] = { "path", "actions" };
	static const char *const netkeys[] = { "domain", "protocol", "port",
	    "ports", "direction", "address", "prefix" };
	static const char *const jailkeys[] = { "jid", "name", "actions" };
	static const char *const vsockkeys[] = { "cid", "port", "ports",
	    "direction" };
	static const char *const execution_jail_keys[] = { "name", "path",
	    "hostname", "ip4_addr" };
	const ucl_object_t *caps, *arr, *v, *x;
	ucl_object_iter_t it;
	bool service_seen[nitems(service_names)];
	unsigned n;

	memset(service_seen, 0, sizeof(service_seen));

	if (ucl_object_type(root) != UCL_OBJECT) {
		snprintf(errbuf, errlen, "manifest must be an object");
		return (-1);
	}
	if (validate_keys(root, "manifest", top, nitems(top), errbuf, errlen) != 0)
		return (-1);
	v = ucl_object_lookup(root, "schema");
	x = ucl_object_lookup(root, "schema_version");
	if ((v == NULL) != (x == NULL)) {
		snprintf(errbuf, errlen,
		    "schema and schema_version must be declared together");
		return (-1);
	}
	if (v != NULL && (ucl_object_type(v) != UCL_STRING ||
	    strcmp(ucl_object_tostring(v),
	    "org.5bsd.serviced.service") != 0)) {
		snprintf(errbuf, errlen,
		    "schema must be 'org.5bsd.serviced.service'");
		return (-1);
	}
	if (x != NULL && (ucl_object_type(x) != UCL_STRING ||
	    strcmp(ucl_object_tostring(x), "1.0.0") != 0)) {
		snprintf(errbuf, errlen, "schema_version must be '1.0.0'");
		return (-1);
	}
	for (n = 0; n < 6; n++) {
		static const char *const strings[] = { "bundle_id", "version",
		    "author", "program", "user", "group" };
		static const size_t limits[] = { CAPBUNDLE_ID_MAX,
		    CAPBUNDLE_VERSION_MAX, CAPBUNDLE_AUTHOR_MAX, PATH_MAX, 64, 64 };
		v = ucl_object_lookup(root, strings[n]);
		if (v != NULL && (ucl_object_type(v) != UCL_STRING ||
		    ucl_object_tostring(v)[0] == '\0' ||
		    strlen(ucl_object_tostring(v)) >= limits[n])) {
			snprintf(errbuf, errlen, "%s must be a non-empty string shorter "
			    "than %zu bytes", strings[n], limits[n]);
			return (-1);
		}
	}
	v = ucl_object_lookup(root, "bundle_id");
	if (v == NULL) {
		snprintf(errbuf, errlen, "bundle_id is required");
		return (-1);
	}
	v = ucl_object_lookup(root, "restart");
	if (v != NULL && (ucl_object_type(v) != UCL_STRING ||
	    (strcmp(ucl_object_tostring(v), "never") != 0 &&
	    strcmp(ucl_object_tostring(v), "always") != 0 &&
	    strcmp(ucl_object_tostring(v), "on-failure") != 0))) {
		snprintf(errbuf, errlen, "invalid restart policy");
		return (-1);
	}
	v = ucl_object_lookup(root, "stop_timeout");
	if (v != NULL && (ucl_object_type(v) != UCL_INT ||
	    ucl_object_toint(v) < 1 || ucl_object_toint(v) > 300)) {
		snprintf(errbuf, errlen, "stop_timeout must be between 1 and 300");
		return (-1);
	}
	v = ucl_object_lookup(root, "max_failures");
	if (v != NULL && (ucl_object_type(v) != UCL_INT ||
	    ucl_object_toint(v) < 1 || ucl_object_toint(v) > 100)) {
		snprintf(errbuf, errlen, "max_failures must be between 1 and 100");
		return (-1);
	}
	if (validate_string_list(root, "provides", CAPBUNDLE_MAX_PROVIDES,
	    CAPBUNDLE_NAME_MAX + 1, errbuf, errlen) != 0 ||
	    validate_string_list(root, "kmod_requires", CAPBUNDLE_MAX_KMOD_REQUIRES,
	    sizeof(((struct capbundle_service *)0)->kmod_requires[0]), errbuf,
	    errlen) != 0 ||
	    validate_string_list(root, "arguments", SERVICED_MAX_ARGUMENTS,
	    SERVICED_ARGUMENT_MAX, errbuf, errlen) != 0 ||
	    validate_string_list(root, "components", 3, 16, errbuf,
	    errlen) != 0)
		return (-1);

	arr = ucl_object_lookup(root, "components");
	if (arr != NULL) {
		const ucl_object_t *entry;
		ucl_object_iter_t components_it;
		const char *name, *first;

		first = NULL;
		components_it = NULL;
		do {
			entry = ucl_object_type(arr) == UCL_STRING ? arr :
			    ucl_object_iterate(arr, &components_it, true);
			if (entry == NULL)
				break;
			name = ucl_object_tostring(entry);
			if (strcmp(name, "filesystem") != 0 &&
			    strcmp(name, "network") != 0 &&
			    strcmp(name, "crypto") != 0) {
				snprintf(errbuf, errlen,
				    "components accepts only 'filesystem' and "
				    "'network' and 'crypto'");
				return (-1);
			}
			if (first != NULL && strcmp(first, name) == 0) {
				snprintf(errbuf, errlen,
				    "components contains duplicate '%s'", name);
				return (-1);
			}
			first = name;
		} while (ucl_object_type(arr) != UCL_STRING);
	}

	arr = ucl_object_lookup(root, "jail");
	if (arr != NULL) {
		const ucl_object_t *name, *jail_path, *hostname, *ip4_addr;
		const char *p;
		struct in_addr address;

		if (ucl_object_type(arr) != UCL_OBJECT) {
			snprintf(errbuf, errlen, "jail must be an object");
			return (-1);
		}
		if (validate_keys(arr, "jail", execution_jail_keys,
		    nitems(execution_jail_keys), errbuf, errlen) != 0)
			return (-1);
		name = ucl_object_lookup(arr, "name");
		jail_path = ucl_object_lookup(arr, "path");
		hostname = ucl_object_lookup(arr, "hostname");
		ip4_addr = ucl_object_lookup(arr, "ip4_addr");
		if (name == NULL || ucl_object_type(name) != UCL_STRING ||
		    ucl_object_tostring(name)[0] == '\0' ||
		    strlen(ucl_object_tostring(name)) >=
		    sizeof(((struct capbundle_service *)0)->jail_name)) {
			snprintf(errbuf, errlen,
			    "jail requires a valid non-empty name");
			return (-1);
		}
		for (p = ucl_object_tostring(name); *p != '\0'; p++) {
			if (!(isalnum((unsigned char)*p) || *p == '.' ||
			    *p == '_' || *p == '-')) {
				snprintf(errbuf, errlen,
				    "jail name contains invalid characters");
				return (-1);
			}
		}
		if (jail_path == NULL ||
		    ucl_object_type(jail_path) != UCL_STRING ||
		    ucl_object_tostring(jail_path)[0] != '/' ||
		    strlen(ucl_object_tostring(jail_path)) >= PATH_MAX) {
			snprintf(errbuf, errlen,
			    "jail requires an absolute path");
			return (-1);
		}
		if (hostname != NULL &&
		    (ucl_object_type(hostname) != UCL_STRING ||
		    ucl_object_tostring(hostname)[0] == '\0' ||
		    strlen(ucl_object_tostring(hostname)) >=
		    sizeof(((struct capbundle_service *)0)->jail_hostname))) {
			snprintf(errbuf, errlen, "jail has an invalid hostname");
			return (-1);
		}
		if (ip4_addr != NULL &&
		    (ucl_object_type(ip4_addr) != UCL_STRING ||
		    inet_pton(AF_INET, ucl_object_tostring(ip4_addr),
		    &address) != 1)) {
			snprintf(errbuf, errlen, "jail has an invalid ip4_addr");
			return (-1);
		}
	}

	arr = ucl_object_lookup(root, "kmod_requires");
	if (arr != NULL) {
		it = NULL;
		while ((v = ucl_object_iterate(arr, &it, true)) != NULL) {
			const char *name, *p;

			name = ucl_object_tostring(v);
			for (p = name; *p != '\0'; p++)
				if (!(isalnum((unsigned char)*p) || *p == '_' ||
				    *p == '-' || *p == '.')) {
					snprintf(errbuf, errlen,
					    "invalid kernel module name '%s'", name);
					return (-1);
				}
		}
	}

	/* Arguments are deliberately an array: a scalar is too easy to mistake
	 * for shell text, and serviced never performs shell splitting. */
	arr = ucl_object_lookup(root, "arguments");
	if (arr != NULL && ucl_object_type(arr) != UCL_ARRAY) {
		snprintf(errbuf, errlen, "arguments must be an array");
		return (-1);
	}

	arr = ucl_object_lookup(root, "environment");
	if (arr != NULL) {
		if (ucl_object_type(arr) != UCL_OBJECT) {
			snprintf(errbuf, errlen, "environment must be an object");
			return (-1);
		}
		n = 0;
		it = NULL;
		while ((v = ucl_object_iterate(arr, &it, true)) != NULL) {
			const char *key = ucl_object_key(v), *p;
			if (++n > SERVICED_MAX_ENVIRONMENT || key == NULL ||
			    key[0] == '\0' || strncmp(key, "ORACLED_", 8) == 0 ||
			    strncmp(key, "SERVICED_", 9) == 0 ||
			    strcmp(key, "SERVICE_BOOTSTRAP_FD") == 0 ||
			    strcmp(key, "NETWORKCMP") == 0 ||
			    strcmp(key, "FILESYSTEMCMP") == 0 ||
			    strcmp(key, "LOGCMP") == 0 ||
			    strcmp(key, "TRACECMP") == 0 ||
			    strcmp(key, "NOTIFYCMP") == 0 ||
			    ucl_object_type(v) != UCL_STRING) {
				snprintf(errbuf, errlen, "invalid environment entry");
				return (-1);
			}
			for (p = key; *p != '\0'; p++)
				if (!(isalnum((unsigned char)*p) || *p == '_') ||
				    (p == key && isdigit((unsigned char)*p))) {
					snprintf(errbuf, errlen,
					    "invalid environment name '%s'", key);
					return (-1);
				}
			if (strlen(key) + strlen(ucl_object_tostring(v)) + 2 >
			    SERVICED_ENVIRONMENT_MAX) {
				snprintf(errbuf, errlen, "environment entry '%s' is too long",
				    key);
				return (-1);
			}
		}
	}

	caps = ucl_object_lookup(root, "capabilities");
	if (caps == NULL)
		return (0);
	if (ucl_object_type(caps) != UCL_OBJECT) {
		snprintf(errbuf, errlen, "capabilities must be an object");
		return (-1);
	}
	if (validate_keys(caps, "capabilities", capkeys, nitems(capkeys),
	    errbuf, errlen) != 0)
		return (-1);

#define VALIDATE_CAP_ARRAY(name, max) do { \
	arr = ucl_object_lookup(caps, (name)); \
	if (arr != NULL && ucl_object_type(arr) != UCL_ARRAY) { \
		snprintf(errbuf, errlen, "capabilities.%s must be an array", (name)); \
		return (-1); \
	} \
	if (arr != NULL && ucl_array_size(arr) > (unsigned)(max)) { \
		snprintf(errbuf, errlen, "capabilities.%s has too many entries", (name)); \
		return (-1); \
	} \
} while (0)
	VALIDATE_CAP_ARRAY("paths", CAPBUNDLE_MAX_CAP_PATHS);
	VALIDATE_CAP_ARRAY("files", CAPBUNDLE_MAX_CAP_FILES);
	VALIDATE_CAP_ARRAY("network", CAPBUNDLE_MAX_CAP_NET);
	VALIDATE_CAP_ARRAY("jails", CAPBUNDLE_MAX_CAP_JAIL);
	VALIDATE_CAP_ARRAY("vsock", CAPBUNDLE_MAX_CAP_VSOCK);
	VALIDATE_CAP_ARRAY("services", CAPBUNDLE_MAX_CAP_SERVICES);
	VALIDATE_CAP_ARRAY("storage", CAPBUNDLE_MAX_CAP_STORAGE);
	VALIDATE_CAP_ARRAY("system", nitems(gate_names));
#undef VALIDATE_CAP_ARRAY

	arr = ucl_object_lookup(caps, "paths");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL)
		if (ucl_object_type(v) != UCL_STRING ||
		    ucl_object_tostring(v)[0] != '/' ||
		    strlen(ucl_object_tostring(v)) >= PATH_MAX) {
			snprintf(errbuf, errlen, "invalid capabilities.paths entry");
			return (-1);
		}

	arr = ucl_object_lookup(caps, "system");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		bool found = false;
		unsigned gi;
		if (ucl_object_type(v) != UCL_STRING) {
			snprintf(errbuf, errlen, "invalid capabilities.system entry");
			return (-1);
		}
		for (gi = 0; gi < nitems(gate_names); gi++)
			if (strcmp(ucl_object_tostring(v), gate_names[gi].name) == 0)
				found = true;
		if (!found) {
			snprintf(errbuf, errlen, "unknown system gate '%s'",
			    ucl_object_tostring(v));
			return (-1);
		}
	}

	arr = ucl_object_lookup(caps, "services");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		bool found = false;
		unsigned si;
		if (ucl_object_type(v) != UCL_STRING) {
			snprintf(errbuf, errlen,
			    "invalid capabilities.services entry");
			return (-1);
		}
		for (si = 0; si < nitems(service_names); si++)
			if (strcmp(ucl_object_tostring(v), service_names[si]) == 0) {
				if (service_seen[si]) {
					snprintf(errbuf, errlen,
					    "duplicate capability service '%s'",
					    service_names[si]);
					return (-1);
				}
				service_seen[si] = true;
				found = true;
			}
		if (!found) {
			snprintf(errbuf, errlen, "unknown capability service '%s'",
			    ucl_object_tostring(v));
			return (-1);
		}
	}

	arr = ucl_object_lookup(caps, "files");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		uint64_t actions;
		if (validate_keys(v, "capabilities.files entry", filekeys,
		    nitems(filekeys), errbuf, errlen) != 0)
			return (-1);
		x = ucl_object_lookup(v, "path");
		if (x == NULL || ucl_object_type(x) != UCL_STRING ||
		    ucl_object_tostring(x)[0] != '/' ||
		    strlen(ucl_object_tostring(x)) >= PATH_MAX ||
		    parse_file_actions(ucl_object_lookup(v, "actions"), &actions) != 0) {
			snprintf(errbuf, errlen, "invalid capabilities.files entry");
			return (-1);
		}
	}

	arr = ucl_object_lookup(caps, "storage");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		uint64_t rights;
		uint8_t lifetime;
		const ucl_object_t *lt;

		const ucl_object_t *fl;

		if (validate_keys(v, "capabilities.storage entry", storagekeys,
		    nitems(storagekeys), errbuf, errlen) != 0)
			return (-1);
		x = ucl_object_lookup(v, "name");
		if (x == NULL || ucl_object_type(x) != UCL_STRING ||
		    ucl_object_tostring(x)[0] == '\0' ||
		    strlen(ucl_object_tostring(x)) >= ORT_STORAGE_NAME_MAX ||
		    strchr(ucl_object_tostring(x), '/') != NULL ||
		    strchr(ucl_object_tostring(x), '@') != NULL ||
		    parse_storage_rights(ucl_object_lookup(v, "rights"),
		    &rights) != 0) {
			snprintf(errbuf, errlen,
			    "invalid capabilities.storage entry");
			return (-1);
		}
		fl = ucl_object_lookup(v, "flavor");
		if (fl != NULL && (ucl_object_type(fl) != UCL_STRING ||
		    strlen(ucl_object_tostring(fl)) >= ORT_STORAGE_FLAVOR_MAX)) {
			snprintf(errbuf, errlen,
			    "invalid capabilities.storage flavor");
			return (-1);
		}
		lt = ucl_object_lookup(v, "lifetime");
		if (lt != NULL && (ucl_object_type(lt) != UCL_STRING ||
		    parse_storage_lifetime_string(ucl_object_tostring(lt),
		    &lifetime) != 0)) {
			snprintf(errbuf, errlen,
			    "invalid capabilities.storage lifetime");
			return (-1);
		}
	}

	arr = ucl_object_lookup(caps, "network");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		uint16_t lo = 0, hi = UINT16_MAX;
		uint8_t addr[16], prefix;
		int domain = AF_INET, addr_domain, protocol;
		const char *s, *protocol_name = NULL;
		bool has_specific_address = false;
		if (ucl_object_type(v) != UCL_OBJECT) {
			snprintf(errbuf, errlen,
			    "capabilities.network entries must be objects");
			return (-1);
		}
		if (validate_keys(v, "capabilities.network entry", netkeys,
		    nitems(netkeys), errbuf, errlen) != 0)
			return (-1);
		if (ucl_object_lookup(v, "port") != NULL &&
		    ucl_object_lookup(v, "ports") != NULL) {
			snprintf(errbuf, errlen, "network entry has both port and ports");
			return (-1);
		}
		x = ucl_object_lookup(v, "port");
		if (x == NULL) x = ucl_object_lookup(v, "ports");
		if (parse_port_range_obj(x, &lo, &hi) != 0) {
			snprintf(errbuf, errlen, "invalid network port range");
			return (-1);
		}
		x = ucl_object_lookup(v, "domain");
		if (x != NULL) {
			if (ucl_object_type(x) != UCL_STRING) {
				snprintf(errbuf, errlen, "network domain must be a string");
				return (-1);
			}
			s = ucl_object_tostring(x);
			if (strcmp(s, "inet") == 0)
				domain = AF_INET;
			else if (strcmp(s, "inet6") == 0)
				domain = AF_INET6;
			else if (strcmp(s, "bluetooth") == 0)
				domain = AF_BLUETOOTH;
			else if (strcmp(s, "any") == 0 || strcmp(s, "*") == 0)
				domain = 0;
			else {
				snprintf(errbuf, errlen, "invalid network domain '%s'", s);
				return (-1);
			}
		}
		x = ucl_object_lookup(v, "protocol");
		if (x != NULL && (ucl_object_type(x) != UCL_STRING ||
		    parse_net_protocol_string(ucl_object_tostring(x), &protocol) != 0)) {
			snprintf(errbuf, errlen, "invalid network protocol");
			return (-1);
		}
		if (x != NULL)
			protocol_name = ucl_object_tostring(x);
		if (protocol_name != NULL && domain != 0 &&
		    ((domain == AF_BLUETOOTH &&
		    (strcmp(protocol_name, "tcp") == 0 ||
		    strcmp(protocol_name, "udp") == 0)) ||
		    (domain != AF_BLUETOOTH &&
		    strcmp(protocol_name, "tcp") != 0 &&
		    strcmp(protocol_name, "udp") != 0 &&
		    strcmp(protocol_name, "any") != 0 &&
		    strcmp(protocol_name, "*") != 0))) {
			snprintf(errbuf, errlen,
			    "network protocol is incompatible with domain");
			return (-1);
		}
		x = ucl_object_lookup(v, "direction");
		if (x != NULL && (ucl_object_type(x) != UCL_STRING ||
		    (strcmp(ucl_object_tostring(x), "bind") != 0 &&
		    strcmp(ucl_object_tostring(x), "connect") != 0 &&
		    strcmp(ucl_object_tostring(x), "any") != 0 &&
		    strcmp(ucl_object_tostring(x), "*") != 0))) {
			snprintf(errbuf, errlen, "invalid network direction");
			return (-1);
		}
		x = ucl_object_lookup(v, "address");
		if (x != NULL) {
			if (ucl_object_type(x) != UCL_STRING) {
				snprintf(errbuf, errlen, "network address must be a string");
				return (-1);
			}
			s = ucl_object_tostring(x);
			if ((domain == AF_BLUETOOTH &&
			    parse_bdaddr_string(s, addr, &prefix) != 0) ||
			    (domain != AF_BLUETOOTH &&
			    parse_address_string(s, addr, &prefix, &addr_domain) != 0)) {
				snprintf(errbuf, errlen, "invalid network address '%s'", s);
				return (-1);
			}
			has_specific_address = memcmp(addr,
			    (const uint8_t[16]){ 0 }, sizeof(addr)) != 0;
			if (domain == 0 && has_specific_address) {
				snprintf(errbuf, errlen,
				    "specific network address requires an explicit domain");
				return (-1);
			}
			if (domain == AF_INET && addr_domain == AF_INET6) {
				snprintf(errbuf, errlen, "IPv6 address requires inet6 domain");
				return (-1);
			}
			if (domain == AF_INET6 && addr_domain == AF_INET) {
				snprintf(errbuf, errlen, "IPv4 address requires inet domain");
				return (-1);
			}
		}
		x = ucl_object_lookup(v, "prefix");
		if (x != NULL) {
			int64_t pfx;
			if (ucl_object_type(x) != UCL_INT) {
				snprintf(errbuf, errlen, "network prefix must be an integer");
				return (-1);
			}
			pfx = ucl_object_toint(x);
			if (!has_specific_address) {
				snprintf(errbuf, errlen,
				    "network prefix requires a specific address");
				return (-1);
			}
			if ((domain == AF_BLUETOOTH && pfx != 0 && pfx != 48) ||
			    (domain != AF_BLUETOOTH && (pfx < 0 || pfx > 128 ||
			    (domain == AF_INET && pfx > 32)))) {
				snprintf(errbuf, errlen, "invalid network prefix");
				return (-1);
			}
		}
	}

	arr = ucl_object_lookup(caps, "jails");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		uint32_t actions;
		if (ucl_object_type(v) == UCL_OBJECT &&
		    validate_keys(v, "capabilities.jails entry", jailkeys,
		    nitems(jailkeys), errbuf, errlen) != 0)
			return (-1);
		if (ucl_object_type(v) != UCL_OBJECT &&
		    ucl_object_type(v) != UCL_STRING && ucl_object_type(v) != UCL_INT) {
			snprintf(errbuf, errlen, "invalid capabilities.jails entry");
			return (-1);
		}
		if (ucl_object_type(v) == UCL_OBJECT &&
		    parse_jail_actions(ucl_object_lookup(v, "actions"), &actions) != 0) {
			snprintf(errbuf, errlen, "invalid jail actions");
			return (-1);
		}
		if (ucl_object_type(v) == UCL_INT &&
		    (ucl_object_toint(v) <= 0 || ucl_object_toint(v) > INT32_MAX)) {
			snprintf(errbuf, errlen, "invalid jail jid");
			return (-1);
		}
		if (ucl_object_type(v) == UCL_STRING &&
		    (ucl_object_tostring(v)[0] == '\0' ||
		    strlen(ucl_object_tostring(v)) >= 64)) {
			snprintf(errbuf, errlen, "invalid jail name");
			return (-1);
		}
		if (ucl_object_type(v) == UCL_OBJECT) {
			const ucl_object_t *jid = ucl_object_lookup(v, "jid");
			const ucl_object_t *name = ucl_object_lookup(v, "name");
			if (jid == NULL && name == NULL) {
				snprintf(errbuf, errlen, "jail entry requires jid or name");
				return (-1);
			}
			if (jid != NULL && (ucl_object_type(jid) != UCL_INT ||
			    ucl_object_toint(jid) <= 0 || ucl_object_toint(jid) > INT32_MAX)) {
				snprintf(errbuf, errlen, "invalid jail jid");
				return (-1);
			}
			if (name != NULL && (ucl_object_type(name) != UCL_STRING ||
			    ucl_object_tostring(name)[0] == '\0' ||
			    strlen(ucl_object_tostring(name)) >= 64)) {
				snprintf(errbuf, errlen, "invalid jail name");
				return (-1);
			}
		}
	}
	arr = ucl_object_lookup(caps, "vsock");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		uint32_t lo, hi;
		if (ucl_object_type(v) != UCL_OBJECT) {
			snprintf(errbuf, errlen,
			    "capabilities.vsock entries must be objects");
			return (-1);
		}
		if (validate_keys(v, "capabilities.vsock entry", vsockkeys,
		    nitems(vsockkeys), errbuf, errlen) != 0)
			return (-1);
		if (ucl_object_lookup(v, "port") != NULL &&
		    ucl_object_lookup(v, "ports") != NULL) {
			snprintf(errbuf, errlen, "vsock entry has both port and ports");
			return (-1);
		}
		x = ucl_object_lookup(v, "port");
		if (x == NULL) x = ucl_object_lookup(v, "ports");
		if (parse_vsock_ports(x, &lo, &hi) != 0) {
			snprintf(errbuf, errlen, "invalid vsock port range");
			return (-1);
		}
		x = ucl_object_lookup(v, "cid");
		if (x != NULL && !((ucl_object_type(x) == UCL_INT &&
		    ucl_object_toint(x) >= 0) ||
		    (ucl_object_type(x) == UCL_STRING &&
		    (strcmp(ucl_object_tostring(x), "*") == 0 ||
		    strcmp(ucl_object_tostring(x), "any") == 0)))) {
			snprintf(errbuf, errlen, "invalid vsock cid");
			return (-1);
		}
		x = ucl_object_lookup(v, "direction");
		if (x != NULL && (ucl_object_type(x) != UCL_STRING ||
		    (strcmp(ucl_object_tostring(x), "bind") != 0 &&
		    strcmp(ucl_object_tostring(x), "connect") != 0 &&
		    strcmp(ucl_object_tostring(x), "any") != 0 &&
		    strcmp(ucl_object_tostring(x), "*") != 0))) {
			snprintf(errbuf, errlen, "invalid vsock direction");
			return (-1);
		}
	}
	return (0);
}

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

static int
parse_components(const ucl_object_t *root, struct capbundle_service *svc,
    char *errbuf, size_t errlen)
{
	const ucl_object_t *components, *entry;
	struct serviced_component *component;
	ucl_object_iter_t it;
	const char *name, *provider;

	(void)errbuf;
	(void)errlen;
	components = ucl_object_lookup(root, "components");
	if (components == NULL)
		return (0);
	it = NULL;
	do {
		entry = ucl_object_type(components) == UCL_STRING ?
		    components : ucl_object_iterate(components, &it, true);
		if (entry == NULL)
			break;
		name = ucl_object_tostring(entry);
		component = &svc->components[svc->ncomponents];
		strlcpy(component->name, name, sizeof(component->name));
		provider = strcmp(name, "filesystem") == 0 ?
		    "org.5bsd.FileSystemCmp" : strcmp(name, "network") == 0 ?
		    "org.5bsd.NetworkCmp" : "org.5bsd.CryptoCmp";
		for (unsigned i = 0; i < svc->nstartup_after; i++)
			if (strcmp(svc->startup_after[i], provider) == 0)
				goto dependency_present;
		if (svc->nstartup_after >= SERVICED_MAX_COMPONENTS) {
			snprintf(errbuf, errlen,
			    "components exceed the startup-edge limit");
			return (-1);
		}
		strlcpy(svc->startup_after[svc->nstartup_after++], provider,
		    sizeof(svc->startup_after[0]));
dependency_present:
		svc->ncomponents++;
	} while (ucl_object_type(components) != UCL_STRING);
	return (0);
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

	if (!ucl_parser_add_file_full(parser, path, 0, UCL_DUPLICATE_ERROR,
	    UCL_PARSE_UCL)) {
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

	if (validate_manifest_schema(root, errbuf, errlen) != 0) {
		ucl_object_unref(root);
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

	v = ucl_object_lookup(root, "arguments");
	if (v != NULL) {
		const ucl_object_t *arg;
		ucl_object_iter_t ait = NULL;
		while ((arg = ucl_object_iterate(v, &ait, true)) != NULL)
			strlcpy(svc->arguments[svc->narguments++],
			    ucl_object_tostring(arg), SERVICED_ARGUMENT_MAX);
	}
	v = ucl_object_lookup(root, "environment");
	if (v != NULL) {
		const ucl_object_t *ev;
		ucl_object_iter_t eit = NULL;
		while ((ev = ucl_object_iterate(v, &eit, true)) != NULL)
			(void)snprintf(svc->environment[svc->nenvironment++],
			    SERVICED_ENVIRONMENT_MAX, "%s=%s", ucl_object_key(ev),
			    ucl_object_tostring(ev));
	}

	/* Runtime identity is private and independent from exposed names. */
	if (snprintf(svc->label, sizeof(svc->label), "%s/%s",
	    ucl_object_tostring(ucl_object_lookup(root, "bundle_id")),
	    program) >= (int)sizeof(svc->label)) {
		snprintf(errbuf, errlen,
		    "bundle_id and program produce an overlong runtime identity");
		ucl_object_unref(root);
		return (-1);
	}
	parse_string_array(root, "provides", svc->provides,
	    CAPBUNDLE_MAX_PROVIDES, &svc->nprovides);

	/* Locally injected authority replacements. */
	if (parse_components(root, svc, errbuf, errlen) == -1) {
		ucl_object_unref(root);
		return (-1);
	}

	/* Kernel module requirements */
	parse_string_array_n(root, "kmod_requires", svc->kmod_requires,
	    sizeof(svc->kmod_requires[0]), CAPBUNDLE_MAX_KMOD_REQUIRES,
	    &svc->nkmod_requires);

	/* Restart policy */
	svc->restart = parse_restart_policy(root, path);

	/* Named persistent execution jail. */
	v = ucl_object_lookup(root, "jail");
	if (v != NULL) {
		svc->has_jail = true;
		parse_string_field(v, "name", svc->jail_name,
		    sizeof(svc->jail_name));
		parse_string_field(v, "path", svc->jail_path,
		    sizeof(svc->jail_path));
		parse_string_field(v, "hostname", svc->jail_hostname,
		    sizeof(svc->jail_hostname));
		parse_string_field(v, "ip4_addr", svc->jail_ip4_addr,
		    sizeof(svc->jail_ip4_addr));
	}

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

			/* VSOCK endpoint capabilities. */
			{
				const ucl_object_t *vsocks, *velem, *vv;
				ucl_object_iter_t vit = NULL;
				vsocks = ucl_object_lookup(caps, "vsock");
				while (vsocks != NULL && (velem = ucl_object_iterate(
				    vsocks, &vit, true)) != NULL) {
					struct ort_vsock_claim *vc =
					    &svc->cap_vsock[svc->ncap_vsock];
					const char *dir;
					memset(vc, 0, sizeof(*vc));
					vc->cid = VSOCK_CID_ANY;
					vc->direction = ORT_NET_DIR_BIND;
					vv = ucl_object_lookup(velem, "port");
					if (vv == NULL)
						vv = ucl_object_lookup(velem, "ports");
					if (parse_vsock_ports(vv, &vc->port_min,
					    &vc->port_max) != 0)
						continue;
					vv = ucl_object_lookup(velem, "cid");
					if (vv != NULL && ucl_object_type(vv) == UCL_INT) {
						int64_t cid = ucl_object_toint(vv);
						if (cid < 0)
							continue;
						vc->cid = (uint64_t)cid;
					}
					vv = ucl_object_lookup(velem, "direction");
					if (vv != NULL) {
						dir = ucl_object_tostring(vv);
						if (strcmp(dir, "bind") == 0)
							vc->direction = ORT_NET_DIR_BIND;
						else if (strcmp(dir, "connect") == 0)
							vc->direction = ORT_NET_DIR_CONNECT;
						else if (strcmp(dir, "any") == 0 ||
						    strcmp(dir, "*") == 0)
							vc->direction = ORT_NET_DIR_ANY;
						else
							continue;
					}
					svc->ncap_vsock++;
				}
			}

			{
				const ucl_object_t *stors, *selem, *sv;
				ucl_object_iter_t sit = NULL;
				stors = ucl_object_lookup(caps, "storage");
				while (stors != NULL && svc->ncap_storage <
				    CAPBUNDLE_MAX_CAP_STORAGE &&
				    (selem = ucl_object_iterate(stors, &sit,
				    true)) != NULL) {
					struct ort_storage_claim *sc =
					    &svc->cap_storage[svc->ncap_storage];
					const char *nm, *fv;

					if (ucl_object_type(selem) != UCL_OBJECT)
						continue;
					memset(sc, 0, sizeof(*sc));
					sc->lifetime = ORT_STORAGE_PERSISTENT;
					sv = ucl_object_lookup(selem, "name");
					if (sv == NULL ||
					    ucl_object_type(sv) != UCL_STRING)
						continue;
					nm = ucl_object_tostring(sv);
					if (strlcpy(sc->name, nm,
					    sizeof(sc->name)) >=
					    sizeof(sc->name))
						continue;
					sv = ucl_object_lookup(selem, "flavor");
					if (sv != NULL &&
					    ucl_object_type(sv) == UCL_STRING &&
					    (fv = ucl_object_tostring(sv)) != NULL &&
					    strlcpy(sc->flavor, fv,
					    sizeof(sc->flavor)) >=
					    sizeof(sc->flavor))
						continue;
					if (parse_storage_rights(
					    ucl_object_lookup(selem, "rights"),
					    &sc->rights) != 0)
						continue;
					sv = ucl_object_lookup(selem,
					    "lifetime");
					if (sv != NULL &&
					    parse_storage_lifetime_string(
					    ucl_object_tostring(sv),
					    &sc->lifetime) != 0)
						continue;
					svc->ncap_storage++;
				}
			}

			parse_string_array_n(caps, "services", svc->cap_services,
			    sizeof(svc->cap_services[0]),
			    CAPBUNDLE_MAX_CAP_SERVICES, &svc->ncap_services);
		}
	}

	/* User/group */
	strlcpy(svc->user, SERVICED_DEFAULT_USER, sizeof(svc->user));
	strlcpy(svc->group, SERVICED_DEFAULT_GROUP, sizeof(svc->group));
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

	/* Schema validation above guarantees both lifecycle ranges. */
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

	/* Every declared capability must survive detailed parsing. */
	{
		const ucl_object_t *caps = ucl_object_lookup(root, "capabilities");
#define CHECK_CAP_COUNT(key, field) do { \
		v = caps != NULL ? ucl_object_lookup(caps, (key)) : NULL; \
		if (v != NULL && svc->field != ucl_array_size(v)) \
			goto malformed_capability; \
} while (0)
		CHECK_CAP_COUNT("paths", ncap_paths);
		CHECK_CAP_COUNT("files", ncap_files);
		CHECK_CAP_COUNT("network", ncap_net);
		CHECK_CAP_COUNT("jails", ncap_jail);
		CHECK_CAP_COUNT("vsock", ncap_vsock);
		CHECK_CAP_COUNT("storage", ncap_storage);
		CHECK_CAP_COUNT("services", ncap_services);
#undef CHECK_CAP_COUNT
	}

	ucl_object_unref(root);
	return (0);

malformed_capability:
	if (errbuf != NULL)
		snprintf(errbuf, errlen, "%s: malformed capability entry", path);
	ucl_object_unref(root);
	return (-1);
}
