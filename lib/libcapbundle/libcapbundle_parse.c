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
#include <sys/zfshandle.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <sha256.h>
#include <ucl.h>

#include "claim_parse.h"
#include "gates.h"
#include "libcapbundle_internal.h"

/* Keys accepted inside an activation.socket object (Phase 4). */
static const char *const socket_object_keys[] = { "name", "listen", "backlog" };

static bool
key_in(const char *key, const char *const *allowed, size_t nallowed)
{
	size_t i;

	for (i = 0; i < nallowed; i++)
		if (strcmp(key, allowed[i]) == 0)
			return (true);
	return (false);
}

/* Match the reverse-domain syntax enforced by serviced's name registry. */
static bool
valid_service_name(const char *name, size_t maxlen)
{
	const unsigned char *p;
	size_t len;
	bool has_dot;

	len = strlen(name);
	if (len == 0 || len >= maxlen || name[0] == '.' ||
	    name[len - 1] == '.')
		return (false);
	has_dot = false;
	for (p = (const unsigned char *)name; *p != '\0'; p++) {
		if (*p == '.') {
			if (p > (const unsigned char *)name && p[-1] == '.')
				return (false);
			has_dot = true;
		} else if (!((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
			return (false);
	}
	return (has_dot);
}

static bool
valid_program_name(const char *name)
{
	const unsigned char *p;

	if (name[0] == '\0' || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0 || strchr(name, '/') != NULL)
		return (false);
	for (p = (const unsigned char *)name; *p != '\0'; p++)
		if (iscntrl(*p))
			return (false);
	return (true);
}

/* Unit names are stable identity components and filesystem names. */
static bool
valid_unit_name(const char *name)
{
	const unsigned char *p;
	size_t len;

	len = strlen(name);
	if (len == 0 || len > 63 || name[0] == '-' || name[len - 1] == '-')
		return (false);
	for (p = (const unsigned char *)name; *p != '\0'; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
		    *p == '-'))
			return (false);
	return (true);
}

int
capbundle_storage_dataset_key(char out[ORT_STORAGE_DATASET_MAX],
    const char *bundle_id, const char *unit_name, const char *name,
    uint8_t scope)
{
	static const char domain[] = "org.5bsd.capability-storage.v1";
	SHA256_CTX context;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	const char *scope_name;
	char prefix;
	unsigned i;

	if (out == NULL || bundle_id == NULL || name == NULL ||
	    bundle_id[0] == '\0' || name[0] == '\0' ||
	    (scope != ORT_STORAGE_SCOPE_UNIT &&
	    scope != ORT_STORAGE_SCOPE_SHARED) ||
	    (scope == ORT_STORAGE_SCOPE_UNIT &&
	    (unit_name == NULL || unit_name[0] == '\0'))) {
		errno = EINVAL;
		return (-1);
	}
	scope_name = scope == ORT_STORAGE_SCOPE_SHARED ? "shared" : "unit";
	prefix = scope == ORT_STORAGE_SCOPE_SHARED ? 's' : 'u';
	SHA256_Init(&context);
#define HASH_FIELD(value) do { \
	const char *field_ = (value); \
	SHA256_Update(&context, field_, strlen(field_) + 1); \
} while (0)
	HASH_FIELD(domain);
	HASH_FIELD(bundle_id);
	HASH_FIELD(scope_name);
	HASH_FIELD(scope == ORT_STORAGE_SCOPE_SHARED ? "" : unit_name);
	HASH_FIELD(name);
#undef HASH_FIELD
	SHA256_Final(digest, &context);
	out[0] = prefix;
	out[1] = '-';
	for (i = 0; i < 24; i++)
		(void)snprintf(out + 2 + (i * 2), 3, "%02x", digest[i]);
	out[50] = '\0';
	return (0);
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
    size_t maxlen, bool unique, char *errbuf, size_t errlen)
{
	const ucl_object_t *arr, *v, *prior;
	ucl_object_iter_t it;
	unsigned i, n;

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
		if (unique) {
			for (i = 0; i + 1 < n; i++) {
				prior = ucl_array_find_index(arr, i);
				if (strcmp(ucl_object_tostring(prior),
				    ucl_object_tostring(v)) == 0) {
					snprintf(errbuf, errlen,
					    "%s contains duplicate '%s'", key,
					    ucl_object_tostring(v));
					return (-1);
				}
			}
		}
	}
	return (0);
}

/*
 * A socket activation logical name (Phase 4): the label the listener is
 * delivered to the provider under.  Bounded and restricted to a conservative
 * label charset so it round-trips through the bootstrap capability table.
 */
static bool
socket_name_valid(const char *name)
{
	const unsigned char *p;
	size_t len;

	if (name == NULL)
		return (false);
	len = strlen(name);
	if (len == 0 || len >= SERVICED_LABEL_MAX)
		return (false);
	for (p = (const unsigned char *)name; *p != '\0'; p++)
		if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-'))
			return (false);
	return (true);
}

/*
 * Parse an activation.socket "listen" string into an svc_activation_socket.
 * Accepted forms (Phase 4):
 *
 *   tcp:ADDR:PORT   tcp6:ADDR:PORT   udp:ADDR:PORT   udp6:ADDR:PORT
 *   unix:/abs/path
 *
 * ADDR may be "*" or empty for any (stored as an all-zero address).  For the
 * INET forms ADDR is validated with inet_pton(3) and PORT must be 1..65535.
 * The port sits after the LAST colon so IPv6 literals (which embed colons)
 * parse correctly.  Fills only the domain/socktype/addr/port/unixpath fields;
 * the caller supplies name and backlog.  Returns 0 on success, -1 with a
 * diagnostic in errbuf.
 */
static int
parse_listen_spec(const char *listen, struct svc_activation_socket *s,
    char *errbuf, size_t errlen)
{
	const char *rest, *portstr;
	char addr[INET6_ADDRSTRLEN];
	char *end;
	const char *colon;
	unsigned long port;
	size_t schemelen, addrlen;

	if (listen == NULL || listen[0] == '\0') {
		snprintf(errbuf, errlen, "activation.socket.listen is empty");
		return (-1);
	}
	rest = strchr(listen, ':');
	if (rest == NULL) {
		snprintf(errbuf, errlen,
		    "activation.socket.listen must be scheme:...");
		return (-1);
	}
	schemelen = (size_t)(rest - listen);
	rest++;
	if (schemelen == 4 && strncmp(listen, "unix", 4) == 0) {
		if (rest[0] != '/') {
			snprintf(errbuf, errlen,
			    "activation.socket unix path must be absolute");
			return (-1);
		}
		if (strlen(rest) >= sizeof(s->unixpath)) {
			snprintf(errbuf, errlen,
			    "activation.socket unix path too long (max %zu)",
			    sizeof(s->unixpath) - 1);
			return (-1);
		}
		s->domain = AF_UNIX;
		s->socktype = SOCK_STREAM;
		s->port = 0;
		memset(s->addr, 0, sizeof(s->addr));
		strlcpy(s->unixpath, rest, sizeof(s->unixpath));
		return (0);
	}
	if (schemelen == 3 && strncmp(listen, "tcp", 3) == 0) {
		s->domain = AF_INET;
		s->socktype = SOCK_STREAM;
	} else if (schemelen == 4 && strncmp(listen, "tcp6", 4) == 0) {
		s->domain = AF_INET6;
		s->socktype = SOCK_STREAM;
	} else if (schemelen == 3 && strncmp(listen, "udp", 3) == 0) {
		s->domain = AF_INET;
		s->socktype = SOCK_DGRAM;
	} else if (schemelen == 4 && strncmp(listen, "udp6", 4) == 0) {
		s->domain = AF_INET6;
		s->socktype = SOCK_DGRAM;
	} else {
		snprintf(errbuf, errlen,
		    "activation.socket.listen has an unknown scheme");
		return (-1);
	}
	s->unixpath[0] = '\0';

	/* The port follows the final colon; everything before it is ADDR. */
	colon = strrchr(rest, ':');
	if (colon == NULL) {
		snprintf(errbuf, errlen,
		    "activation.socket.listen must be scheme:ADDR:PORT");
		return (-1);
	}
	portstr = colon + 1;
	addrlen = (size_t)(colon - rest);
	if (addrlen >= sizeof(addr)) {
		snprintf(errbuf, errlen, "activation.socket address too long");
		return (-1);
	}
	memcpy(addr, rest, addrlen);
	addr[addrlen] = '\0';

	errno = 0;
	port = strtoul(portstr, &end, 10);
	if (errno != 0 || end == portstr || *end != '\0' ||
	    port < 1 || port > 65535) {
		snprintf(errbuf, errlen,
		    "activation.socket port must be 1..65535");
		return (-1);
	}
	s->port = (uint16_t)port;

	memset(s->addr, 0, sizeof(s->addr));
	if (addr[0] == '\0' || strcmp(addr, "*") == 0)
		return (0);		/* any address */
	if (s->domain == AF_INET) {
		struct in_addr in4;

		if (inet_pton(AF_INET, addr, &in4) != 1) {
			snprintf(errbuf, errlen,
			    "activation.socket has an invalid IPv4 address");
			return (-1);
		}
		memcpy(s->addr, &in4, sizeof(in4));
	} else {
		struct in6_addr in6;

		if (inet_pton(AF_INET6, addr, &in6) != 1) {
			snprintf(errbuf, errlen,
			    "activation.socket has an invalid IPv6 address");
			return (-1);
		}
		memcpy(s->addr, &in6, sizeof(in6));
	}
	return (0);
}

/*
 * Validate one activation.socket object and, on success, return its parsed
 * form in *out for the caller's duplicate-name bookkeeping.
 */
static int
validate_socket_object(const ucl_object_t *obj, const char *const *socketkeys,
    size_t nsocketkeys, struct svc_activation_socket *out, char *errbuf,
    size_t errlen)
{
	const ucl_object_t *nameobj, *listenobj, *backlogobj;
	const char *name;

	if (ucl_object_type(obj) != UCL_OBJECT) {
		snprintf(errbuf, errlen,
		    "activation.socket must be an object or array of objects");
		return (-1);
	}
	if (validate_keys(obj, "activation.socket", socketkeys, nsocketkeys,
	    errbuf, errlen) != 0)
		return (-1);
	memset(out, 0, sizeof(*out));

	nameobj = ucl_object_lookup(obj, "name");
	if (nameobj == NULL || ucl_object_type(nameobj) != UCL_STRING ||
	    !socket_name_valid(name = ucl_object_tostring(nameobj))) {
		snprintf(errbuf, errlen,
		    "activation.socket requires a valid non-empty 'name'");
		return (-1);
	}
	strlcpy(out->name, name, sizeof(out->name));

	listenobj = ucl_object_lookup(obj, "listen");
	if (listenobj == NULL || ucl_object_type(listenobj) != UCL_STRING) {
		snprintf(errbuf, errlen,
		    "activation.socket requires a 'listen' string");
		return (-1);
	}
	if (parse_listen_spec(ucl_object_tostring(listenobj), out, errbuf,
	    errlen) != 0)
		return (-1);

	out->backlog = 128;
	backlogobj = ucl_object_lookup(obj, "backlog");
	if (backlogobj != NULL) {
		if (ucl_object_type(backlogobj) != UCL_INT ||
		    ucl_object_toint(backlogobj) < 1 ||
		    ucl_object_toint(backlogobj) > 1024) {
			snprintf(errbuf, errlen,
			    "activation.socket.backlog must be 1..1024");
			return (-1);
		}
		out->backlog = (int)ucl_object_toint(backlogobj);
	}
	return (0);
}

/*
 * Validate the whole activation.socket knob: a single object or an array of
 * objects.  Enforces the per-unit socket cap and unique logical names.
 */
static int
validate_socket_block(const ucl_object_t *arr, const char *const *socketkeys,
    size_t nsocketkeys, char *errbuf, size_t errlen)
{
	struct svc_activation_socket parsed[SERVICED_MAX_ACTIVATION_SOCKETS];
	const ucl_object_t *sockobj, *it_obj;
	ucl_object_iter_t it;
	unsigned n, i;

	sockobj = ucl_object_lookup(arr, "socket");
	if (sockobj == NULL)
		return (0);

	n = 0;
	if (ucl_object_type(sockobj) == UCL_OBJECT) {
		if (validate_socket_object(sockobj, socketkeys, nsocketkeys,
		    &parsed[0], errbuf, errlen) != 0)
			return (-1);
		n = 1;
	} else if (ucl_object_type(sockobj) == UCL_ARRAY) {
		if (ucl_array_size(sockobj) == 0) {
			snprintf(errbuf, errlen,
			    "activation.socket must not be empty");
			return (-1);
		}
		it = NULL;
		while ((it_obj = ucl_object_iterate(sockobj, &it, true)) !=
		    NULL) {
			if (n >= SERVICED_MAX_ACTIVATION_SOCKETS) {
				snprintf(errbuf, errlen,
				    "activation.socket has more than %d entries",
				    SERVICED_MAX_ACTIVATION_SOCKETS);
				return (-1);
			}
			if (validate_socket_object(it_obj, socketkeys,
			    nsocketkeys, &parsed[n], errbuf, errlen) != 0)
				return (-1);
			n++;
		}
	} else {
		snprintf(errbuf, errlen,
		    "activation.socket must be an object or array of objects");
		return (-1);
	}

	for (i = 0; i < n; i++) {
		unsigned j;

		for (j = i + 1; j < n; j++)
			if (strcmp(parsed[i].name, parsed[j].name) == 0) {
				snprintf(errbuf, errlen,
				    "activation.socket has duplicate name '%s'",
				    parsed[i].name);
				return (-1);
			}
	}
	return (0);
}

/*
 * Parse a resource-limit value.  Accepts a plain integer (bytes/seconds/count)
 * or, for byte quantities, a size string with a K/M/G/T suffix ("512M").
 * Returns 0 and stores the value, or -1 (with *err) on a bad value.  A value
 * of 0 is legal (e.g. core=0 means no core dumps).
 */
static int
cap_parse_size(const ucl_object_t *o, const char *key, int64_t *out,
    char *err, size_t errlen)
{
	if (ucl_object_type(o) == UCL_INT) {
		int64_t v = ucl_object_toint(o);
		if (v < 0) {
			snprintf(err, errlen, "limits.%s must not be negative",
			    key);
			return (-1);
		}
		*out = v;
		return (0);
	}
	if (ucl_object_type(o) == UCL_STRING) {
		const char *s = ucl_object_tostring(o);
		char *endp = NULL;
		long long v;
		int shift;

		errno = 0;
		v = strtoll(s, &endp, 10);
		if (endp == s || v < 0 || errno != 0) {
			snprintf(err, errlen, "limits.%s: bad size '%s'", key, s);
			return (-1);
		}
		while (*endp == ' ')
			endp++;
		switch (*endp) {
		case 'T': case 't': shift = 4; endp++; break;
		case 'G': case 'g': shift = 3; endp++; break;
		case 'M': case 'm': shift = 2; endp++; break;
		case 'K': case 'k': shift = 1; endp++; break;
		case '\0': shift = 0; break;
		default:
			snprintf(err, errlen, "limits.%s: bad suffix in '%s'",
			    key, s);
			return (-1);
		}
		if (*endp != '\0') {
			snprintf(err, errlen, "limits.%s: trailing junk in '%s'",
			    key, s);
			return (-1);
		}
		/* Apply the 1024^shift multiplier with an overflow guard. */
		while (shift-- > 0) {
			if (v > INT64_MAX / 1024) {
				snprintf(err, errlen,
				    "limits.%s: value '%s' overflows", key, s);
				return (-1);
			}
			v *= 1024;
		}
		*out = (int64_t)v;
		return (0);
	}
	snprintf(err, errlen, "limits.%s must be an integer or size string", key);
	return (-1);
}

/*
 * Parse the "umask" key: an octal string ("0077") or an integer.  Stores a
 * mask in [0,0777].  Returns 0 or -1 (with *err).
 */
static int
cap_parse_umask(const ucl_object_t *o, int *out, char *err, size_t errlen)
{
	long v;

	if (ucl_object_type(o) == UCL_STRING) {
		const char *s = ucl_object_tostring(o);
		char *endp = NULL;

		v = strtol(s, &endp, 8);
		if (endp == s || *endp != '\0') {
			snprintf(err, errlen, "umask: bad octal '%s'", s);
			return (-1);
		}
	} else if (ucl_object_type(o) == UCL_INT) {
		v = (long)ucl_object_toint(o);
	} else {
		snprintf(err, errlen, "umask must be an octal string or integer");
		return (-1);
	}
	if (v < 0 || v > 0777) {
		snprintf(err, errlen, "umask must be in the range 0000..0777");
		return (-1);
	}
	*out = (int)v;
	return (0);
}

/*
 * Parse the "band" key into SVC_BAND_*.  Returns 0 or -1 (with *err).
 */
static int
cap_parse_band(const ucl_object_t *o, int *out, char *err, size_t errlen)
{
	const char *s;

	if (ucl_object_type(o) != UCL_STRING) {
		snprintf(err, errlen, "band must be a string");
		return (-1);
	}
	s = ucl_object_tostring(o);
	if (strcmp(s, "standard") == 0)
		*out = SVC_BAND_STANDARD;
	else if (strcmp(s, "background") == 0)
		*out = SVC_BAND_BACKGROUND;
	else if (strcmp(s, "interactive") == 0)
		*out = SVC_BAND_INTERACTIVE;
	else {
		snprintf(err, errlen,
		    "band must be background, standard, or interactive");
		return (-1);
	}
	return (0);
}

/* Parse one cron field: '*' (wildcard) or a decimal in [lo,hi]. */
static int
cap_parse_cal_field(const char *tok, int lo, int hi, int *out, char *err,
    size_t errlen)
{
	char *endp = NULL;
	long v;

	if (strcmp(tok, "*") == 0) {
		*out = SVC_CAL_ANY;
		return (0);
	}
	v = strtol(tok, &endp, 10);
	if (endp == tok || *endp != '\0' || v < lo || v > hi) {
		snprintf(err, errlen, "schedule: field '%s' out of range %d..%d",
		    tok, lo, hi);
		return (-1);
	}
	*out = (int)v;
	return (0);
}

/*
 * Parse a calendar activation spec (launchd StartCalendarInterval).  Accepts a
 * cron-style 5-field string "MIN HOUR MDAY MONTH WDAY" (number or '*'), or a
 * named alias (hourly/daily/midnight/weekly/monthly/yearly).  Returns 0 filling
 * *cal, or -1 (with *err).
 */
static int
cap_parse_calendar(const char *spec, struct svc_calendar *cal, char *err,
    size_t errlen)
{
	char buf[128], *fields[5], *p, *save;
	int n;

	cal->minute = cal->hour = cal->mday = cal->month = cal->wday =
	    SVC_CAL_ANY;

	/* Named aliases. */
	if (strcmp(spec, "hourly") == 0) {
		cal->minute = 0;
		return (0);
	}
	if (strcmp(spec, "daily") == 0 || strcmp(spec, "midnight") == 0) {
		cal->minute = cal->hour = 0;
		return (0);
	}
	if (strcmp(spec, "weekly") == 0) {
		cal->minute = cal->hour = cal->wday = 0;
		return (0);
	}
	if (strcmp(spec, "monthly") == 0) {
		cal->minute = cal->hour = 0;
		cal->mday = 1;
		return (0);
	}
	if (strcmp(spec, "yearly") == 0 || strcmp(spec, "annually") == 0) {
		cal->minute = cal->hour = 0;
		cal->mday = cal->month = 1;
		return (0);
	}

	if (strlcpy(buf, spec, sizeof(buf)) >= sizeof(buf)) {
		snprintf(err, errlen, "schedule: expression too long");
		return (-1);
	}
	n = 0;
	for (p = strtok_r(buf, " \t", &save); p != NULL;
	    p = strtok_r(NULL, " \t", &save)) {
		if (n >= 5) {
			snprintf(err, errlen,
			    "schedule: expected 5 cron fields or an alias");
			return (-1);
		}
		fields[n++] = p;
	}
	if (n != 5) {
		snprintf(err, errlen,
		    "schedule: expected 5 cron fields (min hour mday month wday) "
		    "or an alias (hourly/daily/weekly/monthly)");
		return (-1);
	}
	if (cap_parse_cal_field(fields[0], 0, 59, &cal->minute, err, errlen) ||
	    cap_parse_cal_field(fields[1], 0, 23, &cal->hour, err, errlen) ||
	    cap_parse_cal_field(fields[2], 1, 31, &cal->mday, err, errlen) ||
	    cap_parse_cal_field(fields[3], 1, 12, &cal->month, err, errlen) ||
	    cap_parse_cal_field(fields[4], 0, 6, &cal->wday, err, errlen))
		return (-1);
	return (0);
}

static int
validate_unit_schema(const ucl_object_t *root, char *errbuf, size_t errlen)
{
	static const char *const top[] = {
	    "program", "activation",
	    "restart", "management", "capabilities", "user", "group",
	    "stop_timeout", "max_failures", "arguments", "environment",
	    "storage", "protect", "limits", "umask", "band", "privileged" };
	static const char *const activationkeys[] = { "boot", "ipc", "timer",
	    "path", "socket", "schedule", "persistent", "queue_directory",
	    "on_mount", "helper" };
	static const char *const timerkeys[] = { "interval" };
	static const char *const pathkeys[] = { "path" };
	static const char *const limitskeys[] = { "memory", "cpu", "nproc",
	    "nofile", "stack", "fsize", "core" };
	static const char *const capkeys[] = { "paths", "files", "network",
	    "jails", "vsock", "services", "system", "open" };
	static const char *const openkeys[] = { "path", "name", "type",
	    "rights", "optional" };
	static const char *const storagekeys[] = { "name", "scope",
	    "rights", "lifetime" };
	static const char *const service_names[] = { "mount", "node",
	    "accounting", "identity" };
	static const char *const filekeys[] = { "path", "actions" };
	static const char *const netkeys[] = { "domain", "protocol", "port",
	    "ports", "direction", "address", "prefix" };
	static const char *const jailkeys[] = { "jid", "name", "actions" };
	static const char *const vsockkeys[] = { "cid", "port", "ports",
	    "direction" };
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
	for (n = 0; n < 3; n++) {
		static const char *const strings[] = { "program", "user", "group" };
		static const size_t limits[] = { PATH_MAX, 64, 64 };
		v = ucl_object_lookup(root, strings[n]);
		if (v != NULL && (ucl_object_type(v) != UCL_STRING ||
		    ucl_object_tostring(v)[0] == '\0' ||
		    strlen(ucl_object_tostring(v)) >= limits[n])) {
			snprintf(errbuf, errlen, "%s must be a non-empty string shorter "
			    "than %zu bytes", strings[n], limits[n]);
			return (-1);
		}
	}
	v = ucl_object_lookup(root, "program");
	if (v != NULL && !valid_program_name(ucl_object_tostring(v))) {
		snprintf(errbuf, errlen,
		    "program must be one valid name below bin/");
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
	v = ucl_object_lookup(root, "management");
	if (v != NULL && (ucl_object_type(v) != UCL_STRING ||
	    (strcmp(ucl_object_tostring(v), "core") != 0 &&
	    strcmp(ucl_object_tostring(v), "system") != 0 &&
	    strcmp(ucl_object_tostring(v), "user") != 0))) {
		snprintf(errbuf, errlen,
		    "management must be \"core\", \"system\", or \"user\"");
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

	/*
	 * limits{} — pre-exec setrlimit ceilings.  Each present key must parse as
	 * a non-negative integer or (for byte quantities) a K/M/G/T size string.
	 */
	v = ucl_object_lookup(root, "limits");
	if (v != NULL) {
		const ucl_object_t *lv;
		unsigned li;
		int64_t scratch;

		if (ucl_object_type(v) != UCL_OBJECT) {
			snprintf(errbuf, errlen, "limits must be an object");
			return (-1);
		}
		if (validate_keys(v, "limits", limitskeys, nitems(limitskeys),
		    errbuf, errlen) != 0)
			return (-1);
		for (li = 0; li < nitems(limitskeys); li++) {
			lv = ucl_object_lookup(v, limitskeys[li]);
			if (lv != NULL && cap_parse_size(lv, limitskeys[li],
			    &scratch, errbuf, errlen) != 0)
				return (-1);
		}
	}

	/* umask — octal string or integer in 0000..0777. */
	v = ucl_object_lookup(root, "umask");
	if (v != NULL) {
		int scratch;

		if (cap_parse_umask(v, &scratch, errbuf, errlen) != 0)
			return (-1);
	}

	/* band — scheduling class name. */
	v = ucl_object_lookup(root, "band");
	if (v != NULL) {
		int scratch;

		if (cap_parse_band(v, &scratch, errbuf, errlen) != 0)
			return (-1);
	}

	if (validate_string_list(root, "arguments", SERVICED_MAX_ARGUMENTS,
	    SERVICED_ARGUMENT_MAX, false, errbuf, errlen) != 0)
		return (-1);

	arr = ucl_object_lookup(root, "activation");
	if (arr == NULL || validate_keys(arr, "activation", activationkeys,
	    nitems(activationkeys), errbuf, errlen) != 0)
		return (-1);
	v = ucl_object_lookup(arr, "boot");
	if (v != NULL && ucl_object_type(v) != UCL_BOOLEAN) {
		snprintf(errbuf, errlen, "activation.boot must be a boolean");
		return (-1);
	}
	if (validate_string_list(arr, "ipc", CAPBUNDLE_MAX_PROVIDES,
	    SERVICED_LABEL_MAX, true, errbuf, errlen) != 0)
		return (-1);
	x = ucl_object_lookup(arr, "ipc");

	/*
	 * activation.timer — monotonic interval source (Phase 5).  v1 supports
	 * only a fixed monotonic period, so interval must be a positive integer
	 * count of seconds.  Calendar/cron strings, persistent catch-up, and
	 * user schedules are deliberately rejected (fail closed) until their
	 * clock-change/suspend/duplicate-fire/crash semantics are specified.
	 */
	{
		const ucl_object_t *timer, *interval;

		timer = ucl_object_lookup(arr, "timer");
		if (timer != NULL) {
			if (ucl_object_type(timer) != UCL_OBJECT) {
				snprintf(errbuf, errlen,
				    "activation.timer must be an object with an "
				    "integer 'interval' (monotonic seconds)");
				return (-1);
			}
			if (validate_keys(timer, "activation.timer", timerkeys,
			    nitems(timerkeys), errbuf, errlen) != 0)
				return (-1);
			interval = ucl_object_lookup(timer, "interval");
			if (interval == NULL) {
				snprintf(errbuf, errlen,
				    "activation.timer requires an 'interval' "
				    "(monotonic seconds)");
				return (-1);
			}
			if (ucl_object_type(interval) != UCL_INT) {
				snprintf(errbuf, errlen,
				    "activation.timer.interval must be an integer "
				    "count of monotonic seconds; calendar and cron "
				    "expressions are not supported");
				return (-1);
			}
			if (ucl_object_toint(interval) < 1 ||
			    ucl_object_toint(interval) > CAPBUNDLE_MAX_TIMER_INTERVAL) {
				snprintf(errbuf, errlen,
				    "activation.timer.interval must be between 1 and "
				    "%d seconds", CAPBUNDLE_MAX_TIMER_INTERVAL);
				return (-1);
			}
		}
	}

	/*
	 * activation.path — kqueue vnode source (Phase 5).  An absolute,
	 * length-bounded path serviced watches for change events.  Events are
	 * only hints: the consumer must re-inspect the path after activation.
	 */
	{
		const ucl_object_t *pathobj, *pv;
		const char *ps;

		pathobj = ucl_object_lookup(arr, "path");
		if (pathobj != NULL) {
			if (ucl_object_type(pathobj) != UCL_OBJECT) {
				snprintf(errbuf, errlen,
				    "activation.path must be an object with an "
				    "absolute 'path' string");
				return (-1);
			}
			if (validate_keys(pathobj, "activation.path", pathkeys,
			    nitems(pathkeys), errbuf, errlen) != 0)
				return (-1);
			pv = ucl_object_lookup(pathobj, "path");
			if (pv == NULL || ucl_object_type(pv) != UCL_STRING) {
				snprintf(errbuf, errlen,
				    "activation.path requires a 'path' string");
				return (-1);
			}
			ps = ucl_object_tostring(pv);
			if (ps[0] != '/') {
				snprintf(errbuf, errlen,
				    "activation.path.path must be absolute");
				return (-1);
			}
			if (ps[0] == '\0' || strlen(ps) >= PATH_MAX) {
				snprintf(errbuf, errlen,
				    "activation.path.path must be a non-empty "
				    "string shorter than %d bytes", PATH_MAX);
				return (-1);
			}
		}
	}

	/*
	 * activation.schedule — calendar source (launchd StartCalendarInterval).
	 * A cron-style 5-field string or a named alias; validated by parsing it.
	 * activation.persistent — anacron-style catch-up (boolean); only
	 * meaningful with a schedule.
	 */
	{
		const ucl_object_t *sched, *pers;
		struct svc_calendar caltmp;

		sched = ucl_object_lookup(arr, "schedule");
		if (sched != NULL) {
			if (ucl_object_type(sched) != UCL_STRING) {
				snprintf(errbuf, errlen,
				    "activation.schedule must be a cron string or "
				    "alias");
				return (-1);
			}
			if (cap_parse_calendar(ucl_object_tostring(sched),
			    &caltmp, errbuf, errlen) != 0)
				return (-1);
			/*
			 * A unit has one timer slot: a monotonic interval and a
			 * wall-clock schedule cannot both drive it.
			 */
			if (ucl_object_lookup(arr, "timer") != NULL) {
				snprintf(errbuf, errlen,
				    "activation.timer and activation.schedule are "
				    "mutually exclusive");
				return (-1);
			}
		}
		pers = ucl_object_lookup(arr, "persistent");
		if (pers != NULL && ucl_object_type(pers) != UCL_BOOLEAN) {
			snprintf(errbuf, errlen,
			    "activation.persistent must be a boolean");
			return (-1);
		}
		if (pers != NULL && sched == NULL) {
			snprintf(errbuf, errlen,
			    "activation.persistent requires a schedule");
			return (-1);
		}
	}

	/*
	 * activation.queue_directory — spool-drain source (launchd
	 * QueueDirectories): an absolute directory kept drained while non-empty.
	 * activation.on_mount — start on any filesystem mount (boolean).
	 */
	{
		const ucl_object_t *qd, *om;

		qd = ucl_object_lookup(arr, "queue_directory");
		if (qd != NULL) {
			const char *qs;

			if (ucl_object_type(qd) != UCL_STRING) {
				snprintf(errbuf, errlen,
				    "activation.queue_directory must be an absolute "
				    "path string");
				return (-1);
			}
			qs = ucl_object_tostring(qd);
			if (qs[0] != '/' || strlen(qs) >= PATH_MAX) {
				snprintf(errbuf, errlen,
				    "activation.queue_directory must be absolute and "
				    "shorter than %d bytes", PATH_MAX);
				return (-1);
			}
		}
		om = ucl_object_lookup(arr, "on_mount");
		if (om != NULL && ucl_object_type(om) != UCL_BOOLEAN) {
			snprintf(errbuf, errlen,
			    "activation.on_mount must be a boolean");
			return (-1);
		}
	}

	/*
	 * activation.socket — manager-owned listener source (Phase 4).  serviced
	 * binds and holds the listening socket; the first inbound connection is
	 * the demand that launches the unit, and the listener is delivered to it
	 * by logical name.  A single object or an array of objects is accepted.
	 */
	if (validate_socket_block(arr, socket_object_keys,
	    nitems(socket_object_keys), errbuf, errlen) != 0)
		return (-1);

	{
		const ucl_object_t *helper = ucl_object_lookup(arr, "helper");

		if (helper != NULL && ucl_object_type(helper) != UCL_BOOLEAN) {
			snprintf(errbuf, errlen,
			    "activation.helper must be a boolean");
			return (-1);
		}
		/*
		 * A private helper is launched on request by a bundle sibling
		 * (service_helper_open), so it needs no other demand source and
		 * publishes no system.* ipc name.
		 */
		if (helper != NULL && ucl_object_toboolean(helper) &&
		    x != NULL) {
			snprintf(errbuf, errlen,
			    "a helper unit must not publish an ipc name");
			return (-1);
		}
		if ((v == NULL || !ucl_object_toboolean(v)) && x == NULL &&
		    (helper == NULL || !ucl_object_toboolean(helper)) &&
		    ucl_object_lookup(arr, "timer") == NULL &&
		    ucl_object_lookup(arr, "path") == NULL &&
		    ucl_object_lookup(arr, "socket") == NULL &&
		    ucl_object_lookup(arr, "schedule") == NULL &&
		    ucl_object_lookup(arr, "queue_directory") == NULL &&
		    ucl_object_lookup(arr, "on_mount") == NULL) {
			snprintf(errbuf, errlen,
			    "activation requires boot=true, at least one ipc "
			    "name, a timer, a path, a socket, a schedule, a "
			    "queue_directory, on_mount, or helper=true");
			return (-1);
		}
	}
	if (x != NULL && ucl_object_type(x) == UCL_ARRAY &&
	    ucl_array_size(x) == 0) {
		snprintf(errbuf, errlen, "activation.ipc must not be empty");
		return (-1);
	}

	arr = x;
	it = NULL;
	while (arr != NULL && (v = ucl_object_type(arr) == UCL_STRING ? arr :
	    ucl_object_iterate(arr, &it, true)) != NULL) {
		if (!valid_service_name(ucl_object_tostring(v),
		    SERVICED_LABEL_MAX)) {
			snprintf(errbuf, errlen,
			    "activation.ipc contains an invalid reverse-domain name");
			return (-1);
		}
		/*
		 * The "helper." prefix is reserved for the bundle-local names
		 * that service_helper_open() reaches (synthesized below from a
		 * helper unit's own label).  A unit must never publish one via
		 * activation.ipc: that would let a hostile bundle claim/register
		 * another bundle's private-helper name and impersonate or DoS it.
		 */
		if (strncmp(ucl_object_tostring(v), "helper.", 7) == 0) {
			snprintf(errbuf, errlen,
			    "activation.ipc must not use the reserved "
			    "\"helper.\" prefix");
			return (-1);
		}
		if (ucl_object_type(arr) == UCL_STRING)
			break;
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
			    key[0] == '\0' || strncmp(key, "AUTHORITYD_", 8) == 0 ||
			    strncmp(key, "SERVICED_", 9) == 0 ||
			    strcmp(key, "SERVICE_BOOTSTRAP_FD") == 0 ||
			    strcmp(key, "CAPABILITY_UNIT_DIR") == 0 ||
			    strcmp(key, "NETWORKCMP") == 0 ||
			    strcmp(key, "CRYPTOCMP") == 0 ||
			    strcmp(key, "LOGCMP") == 0 ||
			    strcmp(key, "TRACECMP") == 0 ||
			    strcmp(key, "NOTIFY") == 0 ||
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
		goto validate_storage;
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
	VALIDATE_CAP_ARRAY("system", nitems(gate_names));
	VALIDATE_CAP_ARRAY("open", SERVICED_MAX_CAP_OPEN);
#undef VALIDATE_CAP_ARRAY

	arr = ucl_object_lookup(caps, "paths");
	it = NULL;
	n = 0;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(v) != UCL_STRING ||
		    ucl_object_tostring(v)[0] != '/' ||
		    strlen(ucl_object_tostring(v)) >= PATH_MAX) {
			snprintf(errbuf, errlen, "invalid capabilities.paths entry");
			return (-1);
		}
		for (unsigned i = 0; i < n; i++)
			if (strcmp(ucl_object_tostring(ucl_array_find_index(arr, i)),
			    ucl_object_tostring(v)) == 0) {
				snprintf(errbuf, errlen,
				    "duplicate capabilities.paths entry");
				return (-1);
			}
		n++;
	}

	arr = ucl_object_lookup(caps, "system");
	it = NULL;
	n = 0;
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
		for (unsigned i = 0; i < n; i++)
			if (strcmp(ucl_object_tostring(ucl_array_find_index(arr, i)),
			    ucl_object_tostring(v)) == 0) {
				snprintf(errbuf, errlen,
				    "duplicate system gate '%s'",
				    ucl_object_tostring(v));
				return (-1);
			}
		n++;
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

	arr = ucl_object_lookup(caps, "open");
	it = NULL;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		const char *t;
		if (validate_keys(v, "capabilities.open entry", openkeys,
		    nitems(openkeys), errbuf, errlen) != 0)
			return (-1);
		x = ucl_object_lookup(v, "path");
		if (x == NULL || ucl_object_type(x) != UCL_STRING ||
		    ucl_object_tostring(x)[0] != '/' ||
		    strlen(ucl_object_tostring(x)) >= PATH_MAX) {
			snprintf(errbuf, errlen,
			    "invalid capabilities.open path");
			return (-1);
		}
		x = ucl_object_lookup(v, "name");
		if (x == NULL || ucl_object_type(x) != UCL_STRING) {
			snprintf(errbuf, errlen,
			    "invalid capabilities.open name");
			return (-1);
		} else {
			/*
			 * Must satisfy service_capability_name_valid: a bare
			 * [a-z0-9-] token, no leading/trailing hyphen, short
			 * enough for the bootstrap name slot.  Rejecting here
			 * turns a bad name into a config error rather than a
			 * silent retrieval failure in the service.
			 */
			const char *nm = ucl_object_tostring(x);
			size_t nl = strlen(nm);
			const char *np;

			if (nl == 0 || nl >= 56 || nm[0] == '-' ||
			    nm[nl - 1] == '-') {
				snprintf(errbuf, errlen,
				    "capabilities.open name length/format");
				return (-1);
			}
			for (np = nm; *np != '\0'; np++)
				if (!((*np >= 'a' && *np <= 'z') ||
				    (*np >= '0' && *np <= '9') || *np == '-')) {
					snprintf(errbuf, errlen,
					    "capabilities.open name charset");
					return (-1);
				}
		}
		x = ucl_object_lookup(v, "rights");
		if (x == NULL || ucl_object_type(x) != UCL_STRING ||
		    ucl_object_tostring(x)[0] == '\0') {
			snprintf(errbuf, errlen,
			    "capabilities.open entry requires rights");
			return (-1);
		}
		x = ucl_object_lookup(v, "type");
		if (x != NULL && (ucl_object_type(x) != UCL_STRING ||
		    ((t = ucl_object_tostring(x)),
		    strcmp(t, "file") != 0 && strcmp(t, "dir") != 0))) {
			snprintf(errbuf, errlen,
			    "capabilities.open type must be file or dir");
			return (-1);
		}
		x = ucl_object_lookup(v, "optional");
		if (x != NULL && ucl_object_type(x) != UCL_BOOLEAN) {
			snprintf(errbuf, errlen,
			    "capabilities.open optional must be a boolean");
			return (-1);
		}
	}

validate_storage:
	arr = ucl_object_lookup(root, "storage");
	if (arr != NULL && (ucl_object_type(arr) != UCL_ARRAY ||
	    ucl_array_size(arr) > CAPBUNDLE_MAX_CAP_STORAGE)) {
		snprintf(errbuf, errlen,
		    "storage must be an array with at most %u entries",
		    CAPBUNDLE_MAX_CAP_STORAGE);
		return (-1);
	}
	it = NULL;
	n = 0;
	while (arr != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL) {
		uint64_t rights;
		uint8_t lifetime;
		const ucl_object_t *lt, *scope;
		const char *scope_name;

		if (validate_keys(v, "storage entry", storagekeys,
		    nitems(storagekeys), errbuf, errlen) != 0)
			return (-1);
		x = ucl_object_lookup(v, "name");
		if (x == NULL || ucl_object_type(x) != UCL_STRING ||
		    !valid_unit_name(ucl_object_tostring(x)) ||
		    parse_storage_rights(ucl_object_lookup(v, "rights"),
		    &rights) != 0) {
			snprintf(errbuf, errlen, "invalid storage entry");
			return (-1);
		}
		/*
		 * Delivery composes "storage:<name>" into a
		 * SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX buffer; a name that
		 * cannot fit must fail here, not at launch.
		 */
		if (strlen(ucl_object_tostring(x)) > 55) {
			snprintf(errbuf, errlen,
			    "storage name too long for descriptor delivery");
			return (-1);
		}
		scope = ucl_object_lookup(v, "scope");
		if (scope == NULL || ucl_object_type(scope) != UCL_STRING ||
		    ((scope_name = ucl_object_tostring(scope)) == NULL) ||
		    (strcmp(scope_name, "unit") != 0 &&
		    strcmp(scope_name, "shared") != 0)) {
			snprintf(errbuf, errlen,
			    "storage entry requires scope 'unit' or 'shared'");
			return (-1);
		}
		lt = ucl_object_lookup(v, "lifetime");
		if (strcmp(scope_name, "shared") == 0 && lt != NULL) {
			snprintf(errbuf, errlen,
			    "shared storage references cannot override lifetime");
			return (-1);
		}
		for (unsigned i = 0; i < n; i++) {
			const ucl_object_t *previous;

			previous = ucl_array_find_index(arr, i);
			previous = ucl_object_lookup(previous, "name");
			if (strcmp(ucl_object_tostring(previous),
			    ucl_object_tostring(x)) == 0) {
				snprintf(errbuf, errlen,
				    "duplicate storage claim '%s'",
				    ucl_object_tostring(x));
				return (-1);
			}
		}
		n++;
		if (lt != NULL && (ucl_object_type(lt) != UCL_STRING ||
		    parse_storage_lifetime_string(ucl_object_tostring(lt),
		    &lifetime) != 0)) {
			snprintf(errbuf, errlen, "invalid storage lifetime");
			return (-1);
		}
	}

	if (caps == NULL)
		return (0);

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

/*
 * Management class (§5).  Absent key defaults to SVC_MGMT_SYSTEM, preserving
 * the historical all-system behaviour of the base bundles.  The schema
 * validator has already rejected any string other than core/system/user, so an
 * unrecognised value here can only mean the parser was invoked without that
 * validation; fail safe to the most restrictive interpretation that is still a
 * valid default (system) and log it.
 */
static int
parse_management_class(const ucl_object_t *obj, const char *path)
{
	const ucl_object_t *v;
	const char *s;

	v = ucl_object_lookup(obj, "management");
	if (v == NULL || ucl_object_type(v) != UCL_STRING)
		return (SVC_MGMT_SYSTEM);

	s = ucl_object_tostring(v);
	if (strcmp(s, "system") == 0)
		return (SVC_MGMT_SYSTEM);
	if (strcmp(s, "core") == 0)
		return (SVC_MGMT_CORE);
	if (strcmp(s, "user") == 0)
		return (SVC_MGMT_USER);
	syslog(LOG_WARNING, "capbundle %s: unknown management class: %s",
	    path, s);
	return (SVC_MGMT_SYSTEM);
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
 * Launcher-applied protection policy.  A "protect" array of flag names is
 * mapped to a capprotect CP_SF_* bitmask that serviced installs on the process
 * (by its process descriptor) at pdfork(2) time.  The group aliases "protect"
 * and "restrict" expand to the standard outward and self restriction sets; the
 * union "all" applies everything.
 */
static uint32_t
parse_protect_flags(const ucl_object_t *obj, const char *path)
{
	static const struct { const char *name; uint32_t flag; } protect_names[] = {
		{ "ptrace", CP_SF_PTRACE },	{ "signal", CP_SF_SIGNAL },
		{ "visible", CP_SF_VISIBLE },	{ "wait", CP_SF_WAIT },
		{ "sigkill", CP_SF_SIGKILL },	{ "sigcont", CP_SF_SIGCONT },
		{ "sched", CP_SF_SCHED },	{ "core", CP_SF_CORE },
		{ "ktrace", CP_SF_KTRACE },	{ "noprivs", CP_SF_NOPRIVS },
		{ "nofork", CP_SF_NOFORK },	{ "noipc", CP_SF_NOIPC },
		{ "nofdrecv", CP_SF_NOFDRECV },	{ "noexec", CP_SF_NOEXEC },
		{ "nosock", CP_SF_NOSOCK },
		{ "protect", CP_SF_PROTECT },	{ "restrict", CP_SF_RESTRICT },
		{ "all", CP_SF_ALL },
	};
	const ucl_object_t *arr, *elem;
	ucl_object_iter_t it;
	uint32_t mask;
	unsigned pi;
	bool found;

	arr = ucl_object_lookup(obj, "protect");
	if (arr == NULL)
		return (0);
	mask = 0;
	it = NULL;
	while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_STRING)
			continue;
		const char *name = ucl_object_tostring(elem);
		found = false;
		for (pi = 0; pi < nitems(protect_names); pi++) {
			if (strcmp(name, protect_names[pi].name) == 0) {
				mask |= protect_names[pi].flag;
				found = true;
				break;
			}
		}
		if (!found)
			syslog(LOG_WARNING,
			    "capbundle %s: unknown protect flag: %s", path, name);
	}
	return (mask);
}

/*
 * Parse the sole bundle-level manifest.  No unit metadata is accepted here,
 * and the exact inventory is retained in declaration order.
 */
int
capbundle_parse_bundle_ucl(const char *path, struct capbundle *bundle,
    char *errbuf, size_t errlen)
{
	static const char *const keys[] = { "schema", "schema_version",
	    "bundle_id", "version", "sequence", "author", "publisher",
	    "units", "shared" };
	static const char *const shared_keys[] = { "storage" };
	static const char *const shared_storage_keys[] = { "name",
	    "lifetime" };
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *v, *units, *entry, *shared, *storage;
	ucl_object_iter_t it;
	struct stat sb;
	unsigned i;

	if (bundle == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (stat(path, &sb) == -1 || !S_ISREG(sb.st_mode)) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: missing regular Bundle.ucl", path);
		return (-1);
	}
	if (sb.st_size == 0) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: empty document", path);
		return (-1);
	}
	if (sb.st_size > CAPBUNDLE_MAX_UCL_SIZE) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: file too large", path);
		return (-1);
	}
	parser = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_FILEVARS);
	if (parser == NULL)
		return (-1);
	if (!ucl_parser_add_file_full(parser, path, 0, UCL_DUPLICATE_ERROR,
	    UCL_PARSE_UCL)) {
		if (errbuf != NULL) {
			const char *detail = ucl_parser_get_error(parser);

			snprintf(errbuf, errlen, "%s: %s", path,
			    detail != NULL ? detail : "empty or invalid document");
		}
		ucl_parser_free(parser);
		return (-1);
	}
	root = ucl_parser_get_object(parser);
	ucl_parser_free(parser);
	if (root == NULL || validate_keys(root, "Bundle.ucl", keys,
	    nitems(keys), errbuf, errlen) != 0)
		goto invalid;

	v = ucl_object_lookup(root, "schema");
	if (v == NULL || ucl_object_type(v) != UCL_STRING ||
	    strcmp(ucl_object_tostring(v), CAPBUNDLE_SCHEMA) != 0) {
		snprintf(errbuf, errlen, "schema must be '%s'", CAPBUNDLE_SCHEMA);
		goto invalid;
	}
	v = ucl_object_lookup(root, "schema_version");
	if (v == NULL || ucl_object_type(v) != UCL_INT ||
	    ucl_object_toint(v) != CAPBUNDLE_SCHEMA_VERSION) {
		snprintf(errbuf, errlen, "schema_version must be %d",
		    CAPBUNDLE_SCHEMA_VERSION);
		goto invalid;
	}
	v = ucl_object_lookup(root, "bundle_id");
	if (v == NULL || ucl_object_type(v) != UCL_STRING ||
	    !valid_service_name(ucl_object_tostring(v), CAPBUNDLE_ID_MAX)) {
		snprintf(errbuf, errlen,
		    "bundle_id must be a valid reverse-domain identifier");
		goto invalid;
	}
	strlcpy(bundle->bundle_id, ucl_object_tostring(v),
	    sizeof(bundle->bundle_id));
	v = ucl_object_lookup(root, "version");
	if (v == NULL || ucl_object_type(v) != UCL_STRING ||
	    ucl_object_tostring(v)[0] == '\0' ||
	    strlen(ucl_object_tostring(v)) >= sizeof(bundle->version)) {
		snprintf(errbuf, errlen, "version must be a non-empty short string");
		goto invalid;
	}
	strlcpy(bundle->version, ucl_object_tostring(v), sizeof(bundle->version));
	v = ucl_object_lookup(root, "sequence");
	if (v == NULL || ucl_object_type(v) != UCL_INT ||
	    ucl_object_toint(v) < 1) {
		snprintf(errbuf, errlen, "sequence must be a positive integer");
		goto invalid;
	}
	bundle->sequence = (uint64_t)ucl_object_toint(v);

#define COPY_OPTIONAL_STRING(key, field) do { \
	v = ucl_object_lookup(root, (key)); \
	if (v != NULL && (ucl_object_type(v) != UCL_STRING || \
	    ucl_object_tostring(v)[0] == '\0' || \
	    strlen(ucl_object_tostring(v)) >= sizeof(bundle->field))) { \
		snprintf(errbuf, errlen, "%s must be a non-empty short string", \
		    (key)); \
		goto invalid; \
	} \
	if (v != NULL) \
		strlcpy(bundle->field, ucl_object_tostring(v), \
		    sizeof(bundle->field)); \
} while (0)
	COPY_OPTIONAL_STRING("author", author);
	COPY_OPTIONAL_STRING("publisher", publisher);
#undef COPY_OPTIONAL_STRING

	shared = ucl_object_lookup(root, "shared");
	if (shared != NULL) {
		if (validate_keys(shared, "shared", shared_keys,
		    nitems(shared_keys), errbuf, errlen) != 0)
			goto invalid;
		storage = ucl_object_lookup(shared, "storage");
		if (storage != NULL && (ucl_object_type(storage) != UCL_ARRAY ||
		    ucl_array_size(storage) > CAPBUNDLE_MAX_CAP_STORAGE)) {
			snprintf(errbuf, errlen,
			    "shared.storage must be an array with at most %u entries",
			    CAPBUNDLE_MAX_CAP_STORAGE);
			goto invalid;
		}
		it = NULL;
		while (storage != NULL &&
		    (entry = ucl_object_iterate(storage, &it, true)) != NULL) {
			struct capbundle_shared_storage *ss;
			const ucl_object_t *name, *lifetime;
			unsigned j;

			if (validate_keys(entry, "shared.storage entry",
			    shared_storage_keys, nitems(shared_storage_keys), errbuf,
			    errlen) != 0)
				goto invalid;
			name = ucl_object_lookup(entry, "name");
			lifetime = ucl_object_lookup(entry, "lifetime");
			if (name == NULL || ucl_object_type(name) != UCL_STRING ||
			    !valid_unit_name(ucl_object_tostring(name))) {
				snprintf(errbuf, errlen,
				    "invalid shared.storage entry");
				goto invalid;
			}
			ss = &bundle->shared_storage[bundle->nshared_storage];
			memset(ss, 0, sizeof(*ss));
			ss->lifetime = ORT_STORAGE_PERSISTENT;
			if (lifetime != NULL &&
			    (ucl_object_type(lifetime) != UCL_STRING ||
			    parse_storage_lifetime_string(
			    ucl_object_tostring(lifetime), &ss->lifetime) != 0)) {
				snprintf(errbuf, errlen,
				    "invalid shared.storage lifetime");
				goto invalid;
			}
			for (j = 0; j < bundle->nshared_storage; j++)
				if (strcmp(bundle->shared_storage[j].name,
				    ucl_object_tostring(name)) == 0) {
					snprintf(errbuf, errlen,
					    "duplicate shared storage '%s'",
					    ucl_object_tostring(name));
					goto invalid;
				}
			strlcpy(ss->name, ucl_object_tostring(name), sizeof(ss->name));
			bundle->nshared_storage++;
		}
	}

	units = ucl_object_lookup(root, "units");
	if (units == NULL || ucl_object_type(units) != UCL_ARRAY ||
	    ucl_array_size(units) == 0 ||
	    ucl_array_size(units) > CAPBUNDLE_MAX_SERVICES) {
		snprintf(errbuf, errlen, "units must contain between 1 and %u names",
		    CAPBUNDLE_MAX_SERVICES);
		goto invalid;
	}
	it = NULL;
	while ((entry = ucl_object_iterate(units, &it, true)) != NULL) {
		const char *name;

		if (ucl_object_type(entry) != UCL_STRING ||
		    !valid_unit_name(name = ucl_object_tostring(entry))) {
			snprintf(errbuf, errlen,
			    "units contains an invalid unit name");
			goto invalid;
		}
		if (strlen(bundle->bundle_id) + 1 + strlen(name) >=
		    SERVICED_LABEL_MAX) {
			snprintf(errbuf, errlen,
			    "bundle_id and unit name produce an overlong identity");
			goto invalid;
		}
		for (i = 0; i < bundle->nunit_names; i++)
			if (strcmp(bundle->unit_names[i], name) == 0) {
				snprintf(errbuf, errlen,
				    "units contains duplicate '%s'", name);
				goto invalid;
			}
		strlcpy(bundle->unit_names[bundle->nunit_names++], name,
		    sizeof(bundle->unit_names[0]));
	}
	ucl_object_unref(root);
	return (0);

invalid:
	if (root != NULL)
		ucl_object_unref(root);
	return (-1);
}

/* Parse one Unit.ucl file declared by Bundle.ucl. */
int
capbundle_parse_unit_ucl(const char *path, const char *unit_path,
    const struct capbundle *bundle, const char *unit_name,
    struct capbundle_service *svc, char *errbuf, size_t errlen)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *v, *activation;
	const char *program;
	char bin_path[PATH_MAX];
	struct stat ucl_sb;

	memset(svc, 0, sizeof(*svc));

	/*
	 * Policy defaults that differ from a zeroed struct.  Unspecified rlimits
	 * inherit (SVC_LIMIT_UNSET) rather than clamp to zero; core stays 0 (the
	 * no-core default from memset).  umask_val -1 means "apply the plane
	 * default (0077)".  band 0 is SVC_BAND_STANDARD already.
	 */
	svc->limits.mem = svc->limits.cpu = svc->limits.nproc =
	    svc->limits.nofile = svc->limits.stack = svc->limits.fsize =
	    SVC_LIMIT_UNSET;
	svc->umask_val = -1;

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
	if (ucl_sb.st_size == 0) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: empty document", path);
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

	parser = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_FILEVARS);
	if (parser == NULL) {
		if (errbuf)
			snprintf(errbuf, errlen, "ucl_parser_new failed");
		return (-1);
	}

	if (!ucl_parser_add_file_full(parser, path, 0, UCL_DUPLICATE_ERROR,
	    UCL_PARSE_UCL)) {
		if (errbuf) {
			const char *detail = ucl_parser_get_error(parser);

			snprintf(errbuf, errlen, "%s: %s", path,
			    detail != NULL ? detail : "empty or invalid document");
		}
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

	if (validate_unit_schema(root, errbuf, errlen) != 0) {
		ucl_object_unref(root);
		return (-1);
	}

	/* Program defaults to bin/<unit-name> within the unit bundle. */
	v = ucl_object_lookup(root, "program");
	program = v != NULL ? ucl_object_tostring(v) : unit_name;
	/* Reject path traversal and absolute paths in program name. */
	if (!valid_program_name(program)) {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: invalid program name: %s", path, program);
		ucl_object_unref(root);
		return (-1);
	}
	if (snprintf(bin_path, sizeof(bin_path), "%s/bin/%s",
	    unit_path, program) >= (int)sizeof(bin_path)) {
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
	if (snprintf(svc->label, sizeof(svc->label), "%s/%s", bundle->bundle_id,
	    unit_name) >= SERVICED_LABEL_MAX) {
		snprintf(errbuf, errlen,
		    "bundle_id and program produce an overlong runtime identity");
		ucl_object_unref(root);
		return (-1);
	}
	activation = ucl_object_lookup(root, "activation");
	v = ucl_object_lookup(activation, "boot");
	svc->activation_boot = v != NULL && ucl_object_toboolean(v);
	v = ucl_object_lookup(activation, "helper");
	svc->is_helper = v != NULL && ucl_object_toboolean(v);
	parse_string_array(activation, "ipc", svc->provides,
	    CAPBUNDLE_MAX_PROVIDES, &svc->nprovides);
	/*
	 * A private helper publishes no ipc name; synthesize a bundle-local
	 * provider name so service_helper_open() can reach it through the
	 * on-demand provider machinery, while global lookup — which rejects the
	 * reserved "helper." prefix — cannot.  The name uses the provider-name
	 * charset ([A-Za-z0-9._-], dotted), so the label's '/' becomes '.':
	 * "<bundle-id>/<unit>" -> "helper.<bundle-id>.<unit>".  Injecting it into
	 * provides[] here (rather than only when the manifest is later filled)
	 * ensures the bundle registry indexes the name so on-demand resolution
	 * finds the helper; handle_helper_open() reconstructs the identical name.
	 */
	if (svc->is_helper) {
		char *p;

		(void)snprintf(svc->provides[0], sizeof(svc->provides[0]),
		    "helper.%s", svc->label);
		for (p = svc->provides[0]; *p != '\0'; p++)
			if (*p == '/')
				*p = '.';
		svc->nprovides = 1;
	}

	/*
	 * Activation sources (Phase 5).  Validated by validate_unit_schema()
	 * above; here we only record the accepted values.
	 */
	{
		const ucl_object_t *timer, *interval, *pathobj;

		timer = ucl_object_lookup(activation, "timer");
		if (timer != NULL) {
			interval = ucl_object_lookup(timer, "interval");
			if (interval != NULL)
				svc->timer_interval_sec =
				    (unsigned)ucl_object_toint(interval);
		}
		pathobj = ucl_object_lookup(activation, "path");
		if (pathobj != NULL)
			parse_string_field(pathobj, "path", svc->activation_path,
			    sizeof(svc->activation_path));
	}

	/*
	 * Calendar / queue-directory / mount activation sources.  Validated
	 * above, so the calendar spec re-parses without error here.
	 */
	{
		const ucl_object_t *sched, *pers, *qd, *om;
		char errscratch[128];

		sched = ucl_object_lookup(activation, "schedule");
		if (sched != NULL &&
		    cap_parse_calendar(ucl_object_tostring(sched), &svc->calendar,
		    errscratch, sizeof(errscratch)) == 0) {
			svc->has_calendar = true;
			pers = ucl_object_lookup(activation, "persistent");
			svc->calendar_persistent =
			    pers != NULL && ucl_object_toboolean(pers);
		}
		qd = ucl_object_lookup(activation, "queue_directory");
		if (qd != NULL)
			(void)strlcpy(svc->queue_directory,
			    ucl_object_tostring(qd), sizeof(svc->queue_directory));
		om = ucl_object_lookup(activation, "on_mount");
		svc->activation_on_mount = om != NULL && ucl_object_toboolean(om);
	}

	/*
	 * Socket activation sources (Phase 4).  Already validated above; record
	 * the accepted single object or array.  parse_listen_spec() cannot fail
	 * here because the same string passed validation.
	 */
	{
		const ucl_object_t *sockobj, *it_obj;
		ucl_object_iter_t it;
		char errscratch[256];

		sockobj = ucl_object_lookup(activation, "socket");
		svc->nactivation_sockets = 0;
		if (sockobj != NULL && ucl_object_type(sockobj) == UCL_OBJECT) {
			(void)validate_socket_object(sockobj, socket_object_keys,
			    nitems(socket_object_keys),
			    &svc->activation_sockets[0], errscratch,
			    sizeof(errscratch));
			svc->nactivation_sockets = 1;
		} else if (sockobj != NULL &&
		    ucl_object_type(sockobj) == UCL_ARRAY) {
			it = NULL;
			while ((it_obj = ucl_object_iterate(sockobj, &it, true)) !=
			    NULL &&
			    svc->nactivation_sockets <
			    SERVICED_MAX_ACTIVATION_SOCKETS) {
				(void)validate_socket_object(it_obj, socket_object_keys,
				    nitems(socket_object_keys),
				    &svc->activation_sockets[
				    svc->nactivation_sockets], errscratch,
				    sizeof(errscratch));
				svc->nactivation_sockets++;
			}
		}
	}

	/* Restart policy */
	svc->restart = parse_restart_policy(root, path);

	/* Privileged (non-sandboxed) provider flag. */
	{
		const ucl_object_t *pv = ucl_object_lookup(root, "privileged");

		svc->privileged = pv != NULL && ucl_object_toboolean(pv);
	}

	/* Management class (§5) */
	svc->management = parse_management_class(root, path);

	/*
	 * Pre-exec process policy: limits{} / umask / band.  Validated above, so
	 * the parse helpers cannot fail here; each unset field keeps its default
	 * (limits inherited, umask -1 = plane default, band STANDARD).
	 */
	{
		const ucl_object_t *lim, *lv;
		char errscratch[128];

		lim = ucl_object_lookup(root, "limits");
		if (lim != NULL) {
			if ((lv = ucl_object_lookup(lim, "memory")) != NULL)
				(void)cap_parse_size(lv, "memory", &svc->limits.mem,
				    errscratch, sizeof(errscratch));
			if ((lv = ucl_object_lookup(lim, "cpu")) != NULL)
				(void)cap_parse_size(lv, "cpu", &svc->limits.cpu,
				    errscratch, sizeof(errscratch));
			if ((lv = ucl_object_lookup(lim, "nproc")) != NULL)
				(void)cap_parse_size(lv, "nproc", &svc->limits.nproc,
				    errscratch, sizeof(errscratch));
			if ((lv = ucl_object_lookup(lim, "nofile")) != NULL)
				(void)cap_parse_size(lv, "nofile",
				    &svc->limits.nofile, errscratch,
				    sizeof(errscratch));
			if ((lv = ucl_object_lookup(lim, "stack")) != NULL)
				(void)cap_parse_size(lv, "stack", &svc->limits.stack,
				    errscratch, sizeof(errscratch));
			if ((lv = ucl_object_lookup(lim, "fsize")) != NULL)
				(void)cap_parse_size(lv, "fsize", &svc->limits.fsize,
				    errscratch, sizeof(errscratch));
			if ((lv = ucl_object_lookup(lim, "core")) != NULL)
				(void)cap_parse_size(lv, "core", &svc->limits.core,
				    errscratch, sizeof(errscratch));
		}
		if ((lv = ucl_object_lookup(root, "umask")) != NULL)
			(void)cap_parse_umask(lv, &svc->umask_val, errscratch,
			    sizeof(errscratch));
		if ((lv = ucl_object_lookup(root, "band")) != NULL)
			(void)cap_parse_band(lv, &svc->band, errscratch,
			    sizeof(errscratch));
	}

	/* System capabilities */
	svc->cap_system = parse_cap_system(root, path);

	/* Launcher-applied protection policy */
	svc->protect_flags = parse_protect_flags(root, path);

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

			/*
			 * open = [ { path, name, type=file|dir, rights } ]
			 * Files/dirs serviced opens on the service's behalf and
			 * delivers as named descriptors (docs/service-file-
			 * delivery.md).  Distinct from capabilities.files, which
			 * is a MAC path-access grant, not a delivered fd.
			 */
			{
				const ucl_object_t *opens, *oelem;
				ucl_object_iter_t oit;

				opens = ucl_object_lookup(caps, "open");
				if (opens != NULL) {
					oit = NULL;
					while (svc->ncap_open <
					    CAPBUNDLE_MAX_CAP_OPEN &&
					    (oelem = ucl_object_iterate(opens,
					    &oit, true)) != NULL) {
						const ucl_object_t *ov;
						const char *op, *oname, *otype;
						const char *orights, *rp;
						struct serviced_open_cap *oc;
						uint32_t rmask;

						if (ucl_object_type(oelem) !=
						    UCL_OBJECT)
							continue;
						ov = ucl_object_lookup(oelem,
						    "path");
						if (ov == NULL ||
						    ucl_object_type(ov) !=
						    UCL_STRING)
							continue;
						op = ucl_object_tostring(ov);
						if (op[0] != '/') {
							syslog(LOG_WARNING,
							    "capbundle %s: open "
							    "path must be "
							    "absolute: %s",
							    path, op);
							continue;
						}
						ov = ucl_object_lookup(oelem,
						    "name");
						if (ov == NULL ||
						    ucl_object_type(ov) !=
						    UCL_STRING)
							continue;
						oname = ucl_object_tostring(ov);
						if (oname[0] == '\0') {
							syslog(LOG_WARNING,
							    "capbundle %s: open "
							    "name empty", path);
							continue;
						}
						ov = ucl_object_lookup(oelem,
						    "type");
						otype = (ov != NULL &&
						    ucl_object_type(ov) ==
						    UCL_STRING) ?
						    ucl_object_tostring(ov) :
						    "file";
						ov = ucl_object_lookup(oelem,
						    "rights");
						if (ov == NULL ||
						    ucl_object_type(ov) !=
						    UCL_STRING) {
							syslog(LOG_WARNING,
							    "capbundle %s: open "
							    "%s: rights required",
							    path, oname);
							continue;
						}
						orights =
						    ucl_object_tostring(ov);
						rmask = 0;
						for (rp = orights; *rp != '\0';
						    rp++) {
							switch (*rp) {
							case 'r':
								rmask |=
								SVC_OPEN_READ;
								break;
							case 'w':
								rmask |=
								SVC_OPEN_WRITE;
								break;
							case 'x':
								rmask |=
								SVC_OPEN_EXEC;
								break;
							case 'l':
								rmask |=
								SVC_OPEN_LOOKUP;
								break;
							default:
								break;
							}
						}
						if (rmask == 0) {
							syslog(LOG_WARNING,
							    "capbundle %s: open "
							    "%s: no valid rights "
							    "in \"%s\"", path,
							    oname, orights);
							continue;
						}
						oc = &svc->cap_open[
						    svc->ncap_open];
						strlcpy(oc->path, op, PATH_MAX);
						strlcpy(oc->name, oname,
						    sizeof(oc->name));
						oc->rights = rmask;
						oc->is_dir = (strcmp(otype,
						    "dir") == 0) ? 1 : 0;
						ov = ucl_object_lookup(oelem,
						    "optional");
						oc->optional = (ov != NULL &&
						    ucl_object_toboolean(ov)) ?
						    1 : 0;
						svc->ncap_open++;
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
					struct ort_vsock_claim *vc;

					/* The schema validator bounds the
					 * declaration count, but do not rely
					 * on that pass from here. */
					if (svc->ncap_vsock >=
					    CAPBUNDLE_MAX_CAP_VSOCK)
						break;
					vc = &svc->cap_vsock[svc->ncap_vsock];
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

			parse_string_array_n(caps, "services", svc->cap_services,
			    sizeof(svc->cap_services[0]),
			    CAPBUNDLE_MAX_CAP_SERVICES, &svc->ncap_services);
		}
	}

	/* Storage is a descriptor declaration, separate from policy gates. */
	{
		const ucl_object_t *stors, *selem, *sv;
		ucl_object_iter_t sit = NULL;

		stors = ucl_object_lookup(root, "storage");
		while (stors != NULL && (selem = ucl_object_iterate(stors, &sit,
		    true)) != NULL) {
			struct ort_storage_claim *sc;
			const char *scope_name;
			unsigned i;

			sc = &svc->cap_storage[svc->ncap_storage];
			memset(sc, 0, sizeof(*sc));
			sc->lifetime = ORT_STORAGE_PERSISTENT;
			sv = ucl_object_lookup(selem, "name");
			strlcpy(sc->name, ucl_object_tostring(sv), sizeof(sc->name));
			sv = ucl_object_lookup(selem, "scope");
			scope_name = ucl_object_tostring(sv);
			sc->scope = strcmp(scope_name, "shared") == 0 ?
			    ORT_STORAGE_SCOPE_SHARED : ORT_STORAGE_SCOPE_UNIT;
			if (sc->scope == ORT_STORAGE_SCOPE_SHARED) {
				for (i = 0; i < bundle->nshared_storage; i++)
					if (strcmp(bundle->shared_storage[i].name,
					    sc->name) == 0)
						break;
				if (i == bundle->nshared_storage) {
					snprintf(errbuf, errlen,
					    "unit references undeclared shared storage '%s'",
					    sc->name);
					ucl_object_unref(root);
					return (-1);
				}
				sc->lifetime = bundle->shared_storage[i].lifetime;
			} else {
				sv = ucl_object_lookup(selem, "lifetime");
				if (sv != NULL)
					(void)parse_storage_lifetime_string(
					    ucl_object_tostring(sv), &sc->lifetime);
			}
			(void)parse_storage_rights(ucl_object_lookup(selem, "rights"),
			    &sc->rights);
			if (capbundle_storage_dataset_key(sc->dataset,
			    bundle->bundle_id, unit_name, sc->name, sc->scope) == -1) {
				snprintf(errbuf, errlen,
				    "cannot derive storage dataset key");
				ucl_object_unref(root);
				return (-1);
			}
			svc->ncap_storage++;
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
		CHECK_CAP_COUNT("open", ncap_open);
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
