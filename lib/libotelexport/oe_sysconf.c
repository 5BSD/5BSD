/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * System OpenTelemetry configuration (otel.conf(5)) for libotelexport.
 *
 * Files are loaded with the hardened pattern used by the other 5BSD UCL
 * configuration readers: no symlink following, regular files only,
 * owner root or the effective user, no group/other write access, a size
 * cap, no embedded NUL bytes, and no UCL macros or file variables.
 * Unknown keys and wrongly typed values are errors, so a typo cannot
 * silently fall back to a default.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "otelexport.h"
#include "oe_http.h"
#include "oe_sysconf.h"

#define	UCL_FLAGS	(UCL_PARSER_NO_IMPLICIT_ARRAYS | \
			    UCL_PARSER_DISABLE_MACRO | \
			    UCL_PARSER_NO_FILEVARS | UCL_PARSER_NO_TIME)

static void sc_error(struct oe_sysconf *, const char *, ...)
    __printflike(2, 3);

static void
sc_error(struct oe_sysconf *sc, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(sc->error, sizeof(sc->error), fmt, ap);
	va_end(ap);
}

/* Replace *dst with a copy of src.  Returns -1 on allocation failure. */
static int
set_str(char **dst, const char *src)
{
	char *copy;

	copy = strdup(src);
	if (copy == NULL)
		return (-1);
	free(*dst);
	*dst = copy;
	return (0);
}

void
oe_attrs_free(struct oe_attr *attrs, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		free(__DECONST(char *, attrs[i].name));
		free(__DECONST(char *, attrs[i].value));
	}
	free(attrs);
}

/*
 * Set name=value in a malloc'd attribute array, replacing an existing
 * entry with the same name.  An empty value removes the entry.
 */
static int
attrs_set(struct oe_attr **attrsp, size_t *np, const char *name,
    const char *value, size_t max)
{
	struct oe_attr *attrs;
	char *n, *v;
	size_t i;

	attrs = *attrsp;
	for (i = 0; i < *np; i++) {
		if (strcmp(attrs[i].name, name) != 0)
			continue;
		if (value[0] == '\0') {
			free(__DECONST(char *, attrs[i].name));
			free(__DECONST(char *, attrs[i].value));
			memmove(&attrs[i], &attrs[i + 1],
			    (*np - i - 1) * sizeof(*attrs));
			(*np)--;
			return (0);
		}
		v = strdup(value);
		if (v == NULL)
			return (-1);
		free(__DECONST(char *, attrs[i].value));
		attrs[i].value = v;
		return (0);
	}
	if (value[0] == '\0')
		return (0);
	if (*np >= max) {
		errno = E2BIG;
		return (-1);
	}
	attrs = reallocarray(attrs, *np + 1, sizeof(*attrs));
	if (attrs == NULL)
		return (-1);
	*attrsp = attrs;
	n = strdup(name);
	v = strdup(value);
	if (n == NULL || v == NULL) {
		free(n);
		free(v);
		return (-1);
	}
	attrs[*np].name = n;
	attrs[*np].value = v;
	(*np)++;
	return (0);
}

static void
tail_free(struct oe_sysconf *sc)
{
	size_t i;

	for (i = 0; i < sc->nagent_tail; i++)
		free(sc->agent_tail[i]);
	free(sc->agent_tail);
	sc->agent_tail = NULL;
	sc->nagent_tail = 0;
}

void
oe_sysconf_free(struct oe_sysconf *sc)
{

	free(sc->endpoint);
	free(sc->protocol);
	free(sc->compression);
	free(sc->headers_file);
	oe_attrs_free(sc->headers, sc->nheaders);
	free(sc->host_id_file);
	oe_attrs_free(sc->resource_attrs, sc->nresource_attrs);
	free(sc->spool_dir);
	free(sc->agent_listen);
	free(sc->agent_upstream);
	free(sc->agent_upstream_protocol);
	free(sc->agent_headers_file);
	free(sc->agent_log_level);
	tail_free(sc);
	sc->endpoint = sc->protocol = sc->compression = NULL;
	sc->headers_file = sc->host_id_file = sc->spool_dir = NULL;
	sc->agent_listen = sc->agent_upstream = NULL;
	sc->agent_upstream_protocol = sc->agent_headers_file = NULL;
	sc->agent_log_level = NULL;
	sc->headers = sc->resource_attrs = NULL;
	sc->nheaders = sc->nresource_attrs = 0;
}

int
oe_sysconf_init(struct oe_sysconf *sc)
{

	memset(sc, 0, sizeof(*sc));
	sc->enable = 1;
	sc->timeout_ms = OE_SYSCONF_DEFAULT_TIMEOUT_MS;
	sc->spool_max_bytes = OE_SYSCONF_DEFAULT_SPOOL_MAX;
	sc->agent_tls_verify = 1;
	if (set_str(&sc->endpoint, OE_SYSCONF_DEFAULT_ENDPOINT) != 0 ||
	    set_str(&sc->protocol, OE_SYSCONF_DEFAULT_PROTOCOL) != 0 ||
	    set_str(&sc->compression, OE_SYSCONF_DEFAULT_COMPRESSION) != 0 ||
	    set_str(&sc->headers_file, "") != 0 ||
	    set_str(&sc->host_id_file, OE_SYSCONF_DEFAULT_HOSTID_FILE) != 0 ||
	    set_str(&sc->spool_dir, OE_SYSCONF_DEFAULT_SPOOL_DIR) != 0 ||
	    set_str(&sc->agent_listen, OE_SYSCONF_DEFAULT_LISTEN) != 0 ||
	    set_str(&sc->agent_upstream, "") != 0 ||
	    set_str(&sc->agent_upstream_protocol,
	    OE_SYSCONF_DEFAULT_UPSTREAM_PROTOCOL) != 0 ||
	    set_str(&sc->agent_headers_file, "") != 0 ||
	    set_str(&sc->agent_log_level, "info") != 0) {
		oe_sysconf_free(sc);
		sc_error(sc, "out of memory");
		return (-1);
	}
	return (0);
}

/* ---------------------------------------------------------------- */
/* Hardened file reading						*/

/*
 * Read path into a NUL-terminated malloc'd buffer.  "secret" files
 * (credentials) must have no group or other permission bits at all;
 * other files must not be group/other writable.  Returns 1 if the file
 * does not exist, 0 on success, -1 on error with err filled in.
 */
static int
read_checked(const char *path, size_t max, bool secret, char **textp,
    char *err, size_t errlen)
{
	struct stat st;
	char *text;
	ssize_t r;
	size_t done;
	int fd;

	*textp = NULL;
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		if (errno == ENOENT)
			return (1);
		snprintf(err, errlen, "%s: %s%s", path, strerror(errno),
		    errno == EMLINK || errno == ELOOP ?
		    " (symbolic links are refused)" : "");
		return (-1);
	}
	if (fstat(fd, &st) == -1) {
		snprintf(err, errlen, "%s: %s", path, strerror(errno));
		goto fail;
	}
	if (!S_ISREG(st.st_mode)) {
		snprintf(err, errlen, "%s: not a regular file", path);
		goto fail;
	}
	if (st.st_uid != 0 && st.st_uid != geteuid()) {
		snprintf(err, errlen, "%s: owned by uid %u; must be owned "
		    "by root or uid %u", path, (unsigned)st.st_uid,
		    (unsigned)geteuid());
		goto fail;
	}
	if (secret && (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
		snprintf(err, errlen, "%s: mode %04o gives group or other "
		    "access to credentials; use mode 0600 or 0400", path,
		    (unsigned)(st.st_mode & ALLPERMS));
		goto fail;
	}
	if (!secret && (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		snprintf(err, errlen, "%s: mode %04o is writable by group or "
		    "others", path, (unsigned)(st.st_mode & ALLPERMS));
		goto fail;
	}
	if (st.st_size > (off_t)max) {
		snprintf(err, errlen, "%s: %jd bytes exceeds the %zu byte "
		    "limit", path, (intmax_t)st.st_size, max);
		goto fail;
	}
	text = malloc(max + 2);
	if (text == NULL) {
		snprintf(err, errlen, "%s: out of memory", path);
		goto fail;
	}
	done = 0;
	for (;;) {
		r = read(fd, text + done, max + 1 - done);
		if (r == -1 && errno == EINTR)
			continue;
		if (r == -1) {
			snprintf(err, errlen, "%s: %s", path,
			    strerror(errno));
			free(text);
			goto fail;
		}
		if (r == 0)
			break;
		done += (size_t)r;
		if (done > max) {
			/* The file grew after fstat(). */
			snprintf(err, errlen, "%s: exceeds the %zu byte "
			    "limit", path, max);
			free(text);
			goto fail;
		}
	}
	close(fd);
	if (memchr(text, '\0', done) != NULL) {
		snprintf(err, errlen, "%s: contains a NUL byte", path);
		free(text);
		return (-1);
	}
	text[done] = '\0';
	*textp = text;
	return (0);
fail:
	close(fd);
	return (-1);
}

/* ---------------------------------------------------------------- */
/* Credentials file							*/

static bool
valid_header_name(const char *s, size_t len)
{
	size_t i;

	if (len == 0 || len > OE_SYSCONF_KEY_MAX)
		return (false);
	for (i = 0; i < len; i++) {
		/* RFC 9110 token characters. */
		if (!isalnum((unsigned char)s[i]) &&
		    strchr("!#$%&'*+-.^_`|~", s[i]) == NULL)
			return (false);
	}
	return (true);
}

static bool
valid_header_value(const char *s)
{
	const unsigned char *p;

	if (strlen(s) > OE_SYSCONF_VALUE_MAX)
		return (false);
	for (p = (const unsigned char *)s; *p != '\0'; p++)
		if ((*p < 0x20 && *p != '\t') || *p == 0x7f)
			return (false);
	return (true);
}

int
oe_headers_file_load(const char *path, struct oe_attr **attrsp,
    size_t *np, char *err, size_t errlen)
{
	struct oe_attr *attrs;
	char *text, *line, *next, *colon, *name, *value, *end;
	size_t n, lineno;
	int r;

	*attrsp = NULL;
	*np = 0;
	r = read_checked(path, OE_SYSCONF_HEADERS_FILE_MAX, true, &text,
	    err, errlen);
	if (r == 1) {
		snprintf(err, errlen, "%s: headers file does not exist",
		    path);
		return (-1);
	}
	if (r != 0)
		return (-1);
	attrs = NULL;
	n = 0;
	lineno = 0;
	for (line = text; line != NULL; line = next) {
		lineno++;
		next = strchr(line, '\n');
		if (next != NULL)
			*next++ = '\0';
		end = line + strlen(line);
		if (end > line && end[-1] == '\r')
			*--end = '\0';
		while (*line == ' ' || *line == '\t')
			line++;
		if (*line == '\0' || *line == '#')
			continue;
		colon = strchr(line, ':');
		if (colon == NULL) {
			snprintf(err, errlen, "%s:%zu: expected "
			    "\"Name: value\"", path, lineno);
			goto fail;
		}
		name = line;
		end = colon;
		while (end > name && (end[-1] == ' ' || end[-1] == '\t'))
			end--;
		*end = '\0';
		value = colon + 1;
		while (*value == ' ' || *value == '\t')
			value++;
		end = value + strlen(value);
		while (end > value && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		if (!valid_header_name(name, strlen(name))) {
			snprintf(err, errlen, "%s:%zu: invalid header name",
			    path, lineno);
			goto fail;
		}
		if (!valid_header_value(value) || value[0] == '\0') {
			snprintf(err, errlen, "%s:%zu: invalid or empty "
			    "header value", path, lineno);
			goto fail;
		}
		if (strcasecmp(name, "Content-Length") == 0 ||
		    strcasecmp(name, "Content-Type") == 0 ||
		    strcasecmp(name, "Content-Encoding") == 0 ||
		    strcasecmp(name, "Host") == 0 ||
		    strcasecmp(name, "Connection") == 0) {
			snprintf(err, errlen, "%s:%zu: header %s is set by "
			    "the exporter", path, lineno, name);
			goto fail;
		}
		if (attrs_set(&attrs, &n, name, value,
		    OE_SYSCONF_HEADERS_MAX) != 0) {
			snprintf(err, errlen, "%s:%zu: %s", path, lineno,
			    errno == E2BIG ? "too many headers" :
			    "out of memory");
			goto fail;
		}
	}
	explicit_bzero(text, strlen(text));
	free(text);
	*attrsp = attrs;
	*np = n;
	return (0);
fail:
	free(text);
	oe_attrs_free(attrs, n);
	return (-1);
}

/* ---------------------------------------------------------------- */
/* UCL parsing								*/

/* Fetch a string value; rejects other types and embedded NUL bytes. */
static int
get_string(struct oe_sysconf *sc, const char *file, const char *key,
    const ucl_object_t *obj, size_t max, const char **out)
{
	const char *s;
	size_t len;

	if (ucl_object_type(obj) != UCL_STRING) {
		sc_error(sc, "%s: %s must be a single string", file, key);
		return (-1);
	}
	s = ucl_object_tolstring(obj, &len);
	if (strlen(s) != len) {
		sc_error(sc, "%s: %s contains a NUL byte", file, key);
		return (-1);
	}
	if (len > max) {
		sc_error(sc, "%s: %s is longer than %zu bytes", file, key,
		    max);
		return (-1);
	}
	*out = s;
	return (0);
}

static int
get_path(struct oe_sysconf *sc, const char *file, const char *key,
    const ucl_object_t *obj, char **dst)
{
	const char *s;

	if (get_string(sc, file, key, obj, PATH_MAX - 1, &s) != 0)
		return (-1);
	if (s[0] != '\0' && s[0] != '/') {
		sc_error(sc, "%s: %s must be an absolute path or \"\"", file,
		    key);
		return (-1);
	}
	if (set_str(dst, s) != 0) {
		sc_error(sc, "%s: out of memory", file);
		return (-1);
	}
	return (0);
}

static int
get_url(struct oe_sysconf *sc, const char *file, const char *key,
    const ucl_object_t *obj, bool allow_empty, char **dst)
{
	struct oe_url url;
	const char *s;

	if (get_string(sc, file, key, obj, OE_SYSCONF_VALUE_MAX, &s) != 0)
		return (-1);
	if (!(allow_empty && s[0] == '\0') && oe_url_parse(s, &url) != 0) {
		sc_error(sc, "%s: %s \"%s\" is not an http:// or https:// "
		    "URL", file, key, s);
		return (-1);
	}
	if (set_str(dst, s) != 0) {
		sc_error(sc, "%s: out of memory", file);
		return (-1);
	}
	return (0);
}

static int
get_enum(struct oe_sysconf *sc, const char *file, const char *key,
    const ucl_object_t *obj, const char *const *allowed, char **dst)
{
	const char *s;
	size_t i;

	if (get_string(sc, file, key, obj, OE_SYSCONF_KEY_MAX, &s) != 0)
		return (-1);
	for (i = 0; allowed[i] != NULL; i++)
		if (strcmp(s, allowed[i]) == 0)
			break;
	if (allowed[i] == NULL) {
		sc_error(sc, "%s: %s \"%s\" is not supported", file, key, s);
		return (-1);
	}
	if (set_str(dst, s) != 0) {
		sc_error(sc, "%s: out of memory", file);
		return (-1);
	}
	return (0);
}

static int
get_bool(struct oe_sysconf *sc, const char *file, const char *key,
    const ucl_object_t *obj, int *dst)
{

	if (ucl_object_type(obj) != UCL_BOOLEAN) {
		sc_error(sc, "%s: %s must be true or false", file, key);
		return (-1);
	}
	*dst = ucl_object_toboolean(obj) ? 1 : 0;
	return (0);
}

static int
get_int(struct oe_sysconf *sc, const char *file, const char *key,
    const ucl_object_t *obj, int64_t min, int64_t max, int64_t *dst)
{
	int64_t v;

	if (ucl_object_type(obj) != UCL_INT) {
		sc_error(sc, "%s: %s must be an integer", file, key);
		return (-1);
	}
	v = ucl_object_toint(obj);
	if (v < min || v > max) {
		sc_error(sc, "%s: %s %" PRId64 " is outside %" PRId64
		    "..%" PRId64, file, key, v, min, max);
		return (-1);
	}
	*dst = v;
	return (0);
}

static bool
valid_attr_key(const char *s)
{
	size_t i, len;

	len = strlen(s);
	/* Unsigned wrap: rejects len == 0 as well (UCL already does). */
	if (len - 1 >= OE_SYSCONF_KEY_MAX)
		return (false);
	for (i = 0; i < len; i++)
		if (!isalnum((unsigned char)s[i]) &&
		    strchr("._-/", s[i]) == NULL)
			return (false);
	return (true);
}

static int
parse_resource(struct oe_sysconf *sc, const char *file,
    const ucl_object_t *obj)
{
	const ucl_object_t *cur;
	ucl_object_iter_t it;
	const char *key, *value;

	if (ucl_object_type(obj) != UCL_OBJECT) {
		sc_error(sc, "%s: resource must be an object", file);
		return (-1);
	}
	it = NULL;
	while ((cur = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(cur);
		if (!valid_attr_key(key)) {
			sc_error(sc, "%s: invalid resource attribute name "
			    "\"%s\"", file, key);
			return (-1);
		}
		if (get_string(sc, file, key, cur, OE_SYSCONF_VALUE_MAX,
		    &value) != 0)
			return (-1);
		if (attrs_set(&sc->resource_attrs, &sc->nresource_attrs, key,
		    value, OE_SYSCONF_ATTRS_MAX) != 0) {
			sc_error(sc, "%s: %s", file, errno == E2BIG ?
			    "too many resource attributes" : "out of memory");
			return (-1);
		}
	}
	return (0);
}

static int
parse_spool(struct oe_sysconf *sc, const char *file,
    const ucl_object_t *obj)
{
	const ucl_object_t *cur;
	ucl_object_iter_t it;
	const char *key;
	int64_t v;

	if (ucl_object_type(obj) != UCL_OBJECT) {
		sc_error(sc, "%s: spool must be an object", file);
		return (-1);
	}
	it = NULL;
	while ((cur = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(cur);
		if (strcmp(key, "directory") == 0) {
			if (get_path(sc, file, "spool.directory", cur,
			    &sc->spool_dir) != 0)
				return (-1);
			if (sc->spool_dir[0] == '\0') {
				sc_error(sc, "%s: spool.directory must not "
				    "be empty", file);
				return (-1);
			}
		} else if (strcmp(key, "max_bytes") == 0) {
			if (get_int(sc, file, "spool.max_bytes", cur,
			    (int64_t)OE_SYSCONF_SPOOL_MIN,
			    (int64_t)OE_SYSCONF_SPOOL_LIMIT, &v) != 0)
				return (-1);
			sc->spool_max_bytes = (uint64_t)v;
		} else {
			sc_error(sc, "%s: unknown key spool.%s", file, key);
			return (-1);
		}
	}
	return (0);
}

/* Validate "ipv4:port" or "[ipv6]:port". */
static bool
valid_listen(const char *s)
{
	char host[INET6_ADDRSTRLEN + 2], buf[sizeof(struct in6_addr)];
	const char *colon, *close;
	char *end;
	unsigned long port;
	size_t hlen;
	int af;

	if (s[0] == '[') {
		close = strchr(s, ']');
		if (close == NULL || close[1] != ':')
			return (false);
		hlen = (size_t)(close - s - 1);
		s++;
		colon = close + 1;
		af = AF_INET6;
	} else {
		colon = strrchr(s, ':');
		if (colon == NULL)
			return (false);
		hlen = (size_t)(colon - s);
		af = AF_INET;
	}
	if (hlen == 0 || hlen >= sizeof(host))
		return (false);
	memcpy(host, s, hlen);
	host[hlen] = '\0';
	if (inet_pton(af, host, buf) != 1)
		return (false);
	errno = 0;
	port = strtoul(colon + 1, &end, 10);
	return (isdigit((unsigned char)colon[1]) && *end == '\0' &&
	    errno == 0 && port >= 1 && port <= 65535);
}

static int
parse_tail(struct oe_sysconf *sc, const char *file, const ucl_object_t *obj)
{
	const ucl_object_t *cur;
	ucl_object_iter_t it;
	const char *s;
	char **v;
	size_t n;

	if (ucl_object_type(obj) != UCL_ARRAY) {
		sc_error(sc, "%s: agent.tail must be an array of paths",
		    file);
		return (-1);
	}
	tail_free(sc);
	it = NULL;
	n = 0;
	while ((cur = ucl_object_iterate(obj, &it, true)) != NULL) {
		if (get_string(sc, file, "agent.tail entry", cur,
		    PATH_MAX - 1, &s) != 0)
			return (-1);
		if (s[0] != '/' || strpbrk(s, "\n\r\"',") != NULL) {
			sc_error(sc, "%s: agent.tail entry \"%s\" must be an "
			    "absolute path without quotes or commas", file, s);
			return (-1);
		}
		if (n >= OE_SYSCONF_TAIL_MAX) {
			sc_error(sc, "%s: agent.tail has more than %d "
			    "entries", file, OE_SYSCONF_TAIL_MAX);
			return (-1);
		}
		v = reallocarray(sc->agent_tail, n + 1, sizeof(*v));
		if (v == NULL || (v[n] = strdup(s)) == NULL) {
			if (v != NULL)
				sc->agent_tail = v;
			sc_error(sc, "%s: out of memory", file);
			return (-1);
		}
		sc->agent_tail = v;
		sc->nagent_tail = ++n;
	}
	return (0);
}

static int
parse_agent(struct oe_sysconf *sc, const char *file,
    const ucl_object_t *obj)
{
	static const char *const protocols[] = { "http/protobuf", "grpc",
	    NULL };
	static const char *const levels[] = { "off", "error", "warn",
	    "info", "debug", "trace", NULL };
	const ucl_object_t *cur;
	ucl_object_iter_t it;
	const char *key, *s;

	if (ucl_object_type(obj) != UCL_OBJECT) {
		sc_error(sc, "%s: agent must be an object", file);
		return (-1);
	}
	it = NULL;
	while ((cur = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(cur);
		if (strcmp(key, "listen") == 0) {
			if (get_string(sc, file, "agent.listen", cur,
			    OE_SYSCONF_KEY_MAX, &s) != 0)
				return (-1);
			if (!valid_listen(s)) {
				sc_error(sc, "%s: agent.listen \"%s\" must be "
				    "an IP address and port, e.g. "
				    "127.0.0.1:4318", file, s);
				return (-1);
			}
			if (set_str(&sc->agent_listen, s) != 0) {
				sc_error(sc, "%s: out of memory", file);
				return (-1);
			}
		} else if (strcmp(key, "upstream") == 0) {
			if (get_url(sc, file, "agent.upstream", cur, true,
			    &sc->agent_upstream) != 0)
				return (-1);
		} else if (strcmp(key, "upstream_protocol") == 0) {
			if (get_enum(sc, file, "agent.upstream_protocol", cur,
			    protocols, &sc->agent_upstream_protocol) != 0)
				return (-1);
		} else if (strcmp(key, "headers_file") == 0) {
			if (get_path(sc, file, "agent.headers_file", cur,
			    &sc->agent_headers_file) != 0)
				return (-1);
		} else if (strcmp(key, "tls_verify") == 0) {
			if (get_bool(sc, file, "agent.tls_verify", cur,
			    &sc->agent_tls_verify) != 0)
				return (-1);
		} else if (strcmp(key, "log_level") == 0) {
			if (get_enum(sc, file, "agent.log_level", cur, levels,
			    &sc->agent_log_level) != 0)
				return (-1);
		} else if (strcmp(key, "tail") == 0) {
			if (parse_tail(sc, file, cur) != 0)
				return (-1);
		} else {
			sc_error(sc, "%s: unknown key agent.%s", file, key);
			return (-1);
		}
	}
	return (0);
}

static int
parse_root(struct oe_sysconf *sc, const char *file, const ucl_object_t *root)
{
	static const char *const protocols[] = { "http/json", NULL };
	static const char *const compressions[] = { "gzip", "none", NULL };
	const ucl_object_t *cur;
	ucl_object_iter_t it;
	const char *key, *s;
	int64_t v;

	it = NULL;
	while ((cur = ucl_object_iterate(root, &it, true)) != NULL) {
		key = ucl_object_key(cur);
		if (strcmp(key, "enable") == 0) {
			if (get_bool(sc, file, key, cur, &sc->enable) != 0)
				return (-1);
		} else if (strcmp(key, "endpoint") == 0) {
			if (get_url(sc, file, key, cur, false,
			    &sc->endpoint) != 0)
				return (-1);
		} else if (strcmp(key, "protocol") == 0) {
			s = ucl_object_type(cur) == UCL_STRING ?
			    ucl_object_tostring(cur) : "";
			if (strcmp(s, "http/protobuf") == 0 ||
			    strcmp(s, "grpc") == 0) {
				sc_error(sc, "%s: protocol \"%s\": "
				    "libotelexport implements only "
				    "\"http/json\"; use the local agent "
				    "(agent.upstream_protocol) for %s", file,
				    s, s);
				return (-1);
			}
			if (get_enum(sc, file, key, cur, protocols,
			    &sc->protocol) != 0)
				return (-1);
		} else if (strcmp(key, "compression") == 0) {
			if (get_enum(sc, file, key, cur, compressions,
			    &sc->compression) != 0)
				return (-1);
		} else if (strcmp(key, "timeout_ms") == 0) {
			if (get_int(sc, file, key, cur, 1,
			    OE_SYSCONF_TIMEOUT_MAX_MS, &v) != 0)
				return (-1);
			sc->timeout_ms = (int)v;
		} else if (strcmp(key, "headers_file") == 0) {
			if (get_path(sc, file, key, cur,
			    &sc->headers_file) != 0)
				return (-1);
		} else if (strcmp(key, "host_id_file") == 0) {
			if (get_path(sc, file, key, cur,
			    &sc->host_id_file) != 0)
				return (-1);
		} else if (strcmp(key, "resource") == 0) {
			if (parse_resource(sc, file, cur) != 0)
				return (-1);
		} else if (strcmp(key, "spool") == 0) {
			if (parse_spool(sc, file, cur) != 0)
				return (-1);
		} else if (strcmp(key, "agent") == 0) {
			if (parse_agent(sc, file, cur) != 0)
				return (-1);
		} else {
			sc_error(sc, "%s: unknown key %s", file, key);
			return (-1);
		}
	}
	return (0);
}

static int
load_one(struct oe_sysconf *sc, const char *path)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	char *text;
	int r;

	r = read_checked(path, OE_SYSCONF_FILE_MAX, false, &text, sc->error,
	    sizeof(sc->error));
	if (r == 1)
		return (0);
	if (r != 0)
		return (-1);
	parser = ucl_parser_new(UCL_FLAGS);
	if (parser == NULL) {
		free(text);
		sc_error(sc, "%s: out of memory", path);
		return (-1);
	}
	r = -1;
	root = NULL;
	if (!ucl_parser_add_string(parser, text, strlen(text))) {
		sc_error(sc, "%s: syntax error: %s", path,
		    ucl_parser_get_error(parser));
		goto out;
	}
	root = ucl_parser_get_object(parser);
	/* ucl_object_type(NULL) is UCL_NULL. */
	if (ucl_object_type(root) != UCL_OBJECT) {
		sc_error(sc, "%s: top level must be an object", path);
		goto out;
	}
	r = parse_root(sc, path, root);
out:
	ucl_object_unref(root);
	ucl_parser_free(parser);
	free(text);
	return (r);
}

/*
 * Add host.id from host_id_file (hostid(8) stores a UUID there) unless
 * the resource block already set it.  A missing file is not an error:
 * the host ID is generated on first boot.
 */
static int
add_host_id(struct oe_sysconf *sc)
{
	char *text, *end;
	size_t i, len;
	int r;

	if (sc->host_id_file[0] == '\0')
		return (0);
	for (i = 0; i < sc->nresource_attrs; i++)
		if (strcmp(sc->resource_attrs[i].name, "host.id") == 0)
			return (0);
	r = read_checked(sc->host_id_file, 4096, false, &text, sc->error,
	    sizeof(sc->error));
	if (r == 1)
		return (0);
	if (r != 0)
		return (-1);
	end = strchr(text, '\n');
	if (end != NULL)
		*end = '\0';
	len = strlen(text);
	for (i = 0; i < len; i++)
		if (!isxdigit((unsigned char)text[i]) && text[i] != '-')
			break;
	if (len == 0 || len > 64 || i != len) {
		sc_error(sc, "%s: does not contain a host UUID",
		    sc->host_id_file);
		free(text);
		return (-1);
	}
	r = attrs_set(&sc->resource_attrs, &sc->nresource_attrs, "host.id",
	    text, OE_SYSCONF_ATTRS_MAX + 1);
	free(text);
	if (r != 0) {
		sc_error(sc, "%s: out of memory", sc->host_id_file);
		return (-1);
	}
	return (0);
}

/*
 * Standard path, unless the environment names another one (for tests
 * and trial configurations; ignored by set-id programs).
 */
static const char *
std_path(const char *var, const char *path)
{
	const char *v;

	v = issetugid() ? NULL : getenv(var);
	return (v != NULL ? v : path);
}

int
oe_sysconf_load(struct oe_sysconf *sc, const char *defaults_path,
    const char *path)
{
	char saved[sizeof(sc->error)];

	if (oe_sysconf_init(sc) != 0)
		return (-1);
	if (defaults_path == NULL)
		defaults_path = std_path("OTELCONF_DEFAULTS",
		    OE_SYSCONF_DEFAULTS_PATH);
	if (path == NULL)
		path = std_path("OTELCONF_FILE", OE_SYSCONF_PATH);
	if (defaults_path[0] != '\0' && load_one(sc, defaults_path) != 0)
		goto fail;
	if (path[0] != '\0' && load_one(sc, path) != 0)
		goto fail;
	if (add_host_id(sc) != 0)
		goto fail;
	if (sc->headers_file[0] != '\0' &&
	    oe_headers_file_load(sc->headers_file, &sc->headers,
	    &sc->nheaders, sc->error, sizeof(sc->error)) != 0)
		goto fail;
	return (0);
fail:
	memcpy(saved, sc->error, sizeof(saved));
	oe_sysconf_free(sc);
	(void)oe_sysconf_init(sc);
	memcpy(sc->error, saved, sizeof(saved));
	return (-1);
}

/* ---------------------------------------------------------------- */
/* Layer resolution							*/

/* Append sysconf attributes whose names env did not set. */
static int
merge_missing(struct oe_attr **dstp, size_t *ndstp,
    const struct oe_attr *src, size_t nsrc)
{
	struct oe_attr *dst;
	size_t i, j, n;
	char *name, *value;

	for (i = 0; i < nsrc; i++) {
		for (j = 0; j < *ndstp; j++)
			if (strcmp((*dstp)[j].name, src[i].name) == 0)
				break;
		if (j < *ndstp)
			continue;
		n = *ndstp;
		dst = reallocarray(*dstp, n + 1, sizeof(*dst));
		if (dst == NULL)
			return (-1);
		*dstp = dst;
		name = strdup(src[i].name);
		value = strdup(src[i].value);
		if (name == NULL || value == NULL) {
			free(name);
			free(value);
			return (-1);
		}
		dst[n].name = name;
		dst[n].value = value;
		*ndstp = n + 1;
	}
	return (0);
}

int
oe_env_load_system(struct oe_env *env, const struct oe_sysconf *sc,
    const char *cli_endpoint)
{

	oe_env_load(env);
	if (cli_endpoint != NULL)
		env->endpoint = cli_endpoint;
	if (sc == NULL || !sc->enable)
		return (0);
	if (env->endpoint == NULL)
		env->endpoint = sc->endpoint;
	if (env->compression == NULL)
		env->compression = sc->compression;
	if (env->timeout_ms < 0)
		env->timeout_ms = sc->timeout_ms;
	if (merge_missing(&env->resource_attrs, &env->nresource_attrs,
	    sc->resource_attrs, sc->nresource_attrs) != 0)
		return (-1);
	if (strcmp(env->endpoint, sc->endpoint) == 0 &&
	    merge_missing(&env->headers, &env->nheaders, sc->headers,
	    sc->nheaders) != 0)
		return (-1);
	return (0);
}
