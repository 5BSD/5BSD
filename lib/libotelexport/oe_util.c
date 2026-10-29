/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared utilities: string buffer, JSON escaping, OTel environment
 * variables, host detection, frame and timestamp formatting.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "otelexport.h"
#include "oe_sysconf.h"

void
oe_buf_init(struct oe_buf *b)
{

	b->data = NULL;
	b->len = 0;
	b->cap = 0;
	b->error = 0;
}

void
oe_buf_free(struct oe_buf *b)
{

	free(b->data);
	oe_buf_init(b);
}

static int
oe_buf_reserve(struct oe_buf *b, size_t need)
{
	size_t newcap;
	char *p;

	if (b->error)
		return (-1);
	if (need > SIZE_MAX - b->len - 1) {
		b->error = 1;
		return (-1);
	}
	if (b->len + need + 1 <= b->cap)
		return (0);
	newcap = b->cap == 0 ? 256 : b->cap;
	while (newcap < b->len + need + 1)
		newcap *= 2;
	p = realloc(b->data, newcap);
	if (p == NULL) {
		b->error = 1;
		return (-1);
	}
	b->data = p;
	b->cap = newcap;
	return (0);
}

int
oe_buf_append(struct oe_buf *b, const char *s, size_t len)
{

	if (oe_buf_reserve(b, len) != 0)
		return (-1);
	memcpy(b->data + b->len, s, len);
	b->len += len;
	b->data[b->len] = '\0';
	return (0);
}

int
oe_buf_appendstr(struct oe_buf *b, const char *s)
{

	return (oe_buf_append(b, s, strlen(s)));
}

int
oe_buf_appendf(struct oe_buf *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0) {
		b->error = 1;
		return (-1);
	}
	if (oe_buf_reserve(b, (size_t)n) != 0)
		return (-1);
	va_start(ap, fmt);
	vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap);
	va_end(ap);
	b->len += (size_t)n;
	return (0);
}

/*
 * Length of the well-formed UTF-8 sequence at p (RFC 3629: no
 * overlong forms, no surrogates, nothing above U+10FFFF), or 0.
 */
static size_t
utf8_seqlen(const unsigned char *p)
{
	size_t n, i;
	uint32_t cp;

	if (p[0] < 0x80)
		return (1);
	if (p[0] >= 0xc2 && p[0] <= 0xdf) {
		n = 2;
		cp = p[0] & 0x1f;
	} else if (p[0] >= 0xe0 && p[0] <= 0xef) {
		n = 3;
		cp = p[0] & 0x0f;
	} else if (p[0] >= 0xf0 && p[0] <= 0xf4) {
		n = 4;
		cp = p[0] & 0x07;
	} else
		return (0);
	for (i = 1; i < n; i++) {
		/* A NUL terminator fails this test: no overrun. */
		if ((p[i] & 0xc0) != 0x80)
			return (0);
		cp = (cp << 6) | (p[i] & 0x3f);
	}
	if ((n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) ||
	    cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
		return (0);
	return (n);
}

int
oe_buf_appendjson(struct oe_buf *b, const char *s)
{
	const unsigned char *p;
	char esc[8];
	size_t n;

	if (s == NULL)
		return (0);
	for (p = (const unsigned char *)s; *p != '\0'; p += n) {
		n = 1;
		switch (*p) {
		case '"':
			oe_buf_append(b, "\\\"", 2);
			break;
		case '\\':
			oe_buf_append(b, "\\\\", 2);
			break;
		case '\b':
			oe_buf_append(b, "\\b", 2);
			break;
		case '\f':
			oe_buf_append(b, "\\f", 2);
			break;
		case '\n':
			oe_buf_append(b, "\\n", 2);
			break;
		case '\r':
			oe_buf_append(b, "\\r", 2);
			break;
		case '\t':
			oe_buf_append(b, "\\t", 2);
			break;
		default:
			if (*p < 0x20) {
				snprintf(esc, sizeof(esc), "\\u%04x", *p);
				oe_buf_appendstr(b, esc);
				break;
			}
			/*
			 * Well-formed UTF-8 passes through unchanged.
			 * DTrace strings are arbitrary bytes, so a byte
			 * that does not start a well-formed sequence
			 * becomes U+FFFD, keeping the document valid.
			 */
			n = utf8_seqlen(p);
			if (n == 0) {
				oe_buf_append(b, "\xef\xbf\xbd", 3);
				n = 1;
			} else
				oe_buf_append(b, (const char *)p, n);
			break;
		}
	}
	return (b->error ? -1 : 0);
}

/* Decode %XX escapes in place; -1 on a malformed escape. */
static int
pct_decode(char *s)
{
	char *in, *out, hex[3];

	for (in = out = s; *in != '\0'; in++) {
		if (*in != '%') {
			*out++ = *in;
			continue;
		}
		if (!isxdigit((unsigned char)in[1]) ||
		    !isxdigit((unsigned char)in[2]))
			return (-1);
		hex[0] = in[1];
		hex[1] = in[2];
		hex[2] = '\0';
		*out++ = (char)strtol(hex, NULL, 16);
		in += 2;
	}
	*out = '\0';
	return (0);
}

/* Trim leading and trailing blanks in place; returns the new start. */
static char *
trim(char *s)
{
	char *end;

	while (*s == ' ' || *s == '\t')
		s++;
	end = s + strlen(s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
		*--end = '\0';
	return (s);
}

/* RFC 9110 token characters, for (non-empty) header field names. */
static int
is_token(const char *s)
{

	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) &&
		    strchr("!#$%&'*+-.^_`|~", *s) == NULL)
			return (0);
	return (1);
}

static int
has_ctl(const char *s)
{

	for (; *s != '\0'; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f)
			return (1);
	return (0);
}

static void
free_kvlist(struct oe_attr *attrs, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		free(__DECONST(char *, attrs[i].name));
		free(__DECONST(char *, attrs[i].value));
	}
	free(attrs);
}

/*
 * Parse a comma-separated key=value list (the W3C Baggage-style
 * format of OTEL_RESOURCE_ATTRIBUTES and OTEL_EXPORTER_OTLP_HEADERS)
 * into a malloc'd oe_attr array.  Blanks around keys and values are
 * trimmed and values are percent-decoded.  As the OTel spec asks,
 * any malformed entry discards the whole variable with a warning;
 * for headers that includes names that are not HTTP tokens and
 * values carrying control characters, which would otherwise let the
 * environment inject extra request lines.
 */
static void
oe_parse_kvlist(const char *var, int is_header, struct oe_attr **attrsp,
    size_t *nattrsp)
{
	struct oe_attr *attrs, *np;
	const char *raw, *why;
	char *copy, *pair, *eq, *last, *key, *value;
	size_t n;

	*attrsp = NULL;
	*nattrsp = 0;
	raw = getenv(var);
	if (raw == NULL || *raw == '\0')
		return;
	copy = strdup(raw);
	if (copy == NULL)
		return;
	attrs = NULL;
	n = 0;
	why = NULL;
	for (pair = strtok_r(copy, ",", &last); pair != NULL;
	    pair = strtok_r(NULL, ",", &last)) {
		if (*trim(pair) == '\0')
			continue;	/* tolerate "a=b,,c=d" and "a=b," */
		eq = strchr(pair, '=');
		if (eq == NULL) {
			why = "entry without '='";
			break;
		}
		*eq = '\0';
		key = trim(pair);
		value = trim(eq + 1);
		if (*key == '\0') {
			why = "empty key";
			break;
		}
		if (pct_decode(key) != 0 || pct_decode(value) != 0) {
			why = "malformed percent-encoding";
			break;
		}
		if (is_header && (!is_token(key) || has_ctl(value))) {
			why = "invalid header name or value";
			break;
		}
		np = realloc(attrs, (n + 1) * sizeof(*attrs));
		if (np == NULL) {
			why = "out of memory";
			break;
		}
		attrs = np;
		attrs[n].name = strdup(key);
		attrs[n].value = strdup(value);
		n++;
		if (attrs[n - 1].name == NULL || attrs[n - 1].value == NULL) {
			why = "out of memory";
			break;
		}
	}
	free(copy);
	if (why != NULL) {
		fprintf(stderr, "otelexport: ignoring %s: %s\n", var, why);
		free_kvlist(attrs, n);
		return;
	}
	*attrsp = attrs;
	*nattrsp = n;
}

void
oe_env_load(struct oe_env *env)
{
	const char *timeout;
	char *end;
	long ms;

	memset(env, 0, sizeof(*env));
	env->service_name = getenv("OTEL_SERVICE_NAME");
	if (env->service_name != NULL && env->service_name[0] == '\0')
		env->service_name = NULL;
	env->endpoint = getenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	if (env->endpoint != NULL && env->endpoint[0] == '\0')
		env->endpoint = NULL;
	env->compression = getenv("OTEL_EXPORTER_OTLP_COMPRESSION");
	if (env->compression != NULL &&
	    strcasecmp(env->compression, "gzip") != 0 &&
	    strcasecmp(env->compression, "none") != 0) {
		fprintf(stderr, "otelexport: ignoring "
		    "OTEL_EXPORTER_OTLP_COMPRESSION=%s: expected gzip or "
		    "none\n", env->compression);
		env->compression = NULL;
	}
	env->timeout_ms = -1;
	timeout = getenv("OTEL_EXPORTER_OTLP_TIMEOUT");
	if (timeout != NULL) {
		errno = 0;
		ms = strtol(timeout, &end, 10);
		if (end == timeout || *end != '\0' || errno != 0 || ms < 0 ||
		    ms > INT_MAX)
			fprintf(stderr, "otelexport: ignoring "
			    "OTEL_EXPORTER_OTLP_TIMEOUT=%s: expected "
			    "milliseconds\n", timeout);
		else
			env->timeout_ms = (int)ms;
	}
	oe_parse_kvlist("OTEL_RESOURCE_ATTRIBUTES", 0, &env->resource_attrs,
	    &env->nresource_attrs);
	oe_parse_kvlist("OTEL_EXPORTER_OTLP_HEADERS", 1, &env->headers,
	    &env->nheaders);
}

void
oe_env_free(struct oe_env *env)
{

	free_kvlist(env->resource_attrs, env->nresource_attrs);
	free_kvlist(env->headers, env->nheaders);
	if (env->sysconf != NULL) {
		oe_sysconf_free(env->sysconf);
		free(env->sysconf);
	}
	free(env->spool_buf);
	memset(env, 0, sizeof(*env));
}

void
oe_resource_init(struct oe_resource *r, const struct oe_env *env,
    const struct oe_host_info *hi, const char *service, const char *version)
{
	size_t i;

	memset(r, 0, sizeof(*r));
	oe_resource_host(r, hi);
	/* OTEL_SERVICE_NAME > service.name in the attributes > default. */
	r->service_name = service;
	for (i = 0; i < env->nresource_attrs; i++)
		if (strcmp(env->resource_attrs[i].name, "service.name") == 0)
			r->service_name = env->resource_attrs[i].value;
	if (env->service_name != NULL)
		r->service_name = env->service_name;
	r->service_version = version;
	r->custom = env->resource_attrs;
	r->ncustom = env->nresource_attrs;
}

void
oe_otlp_config_env(struct oe_otlp_config *cfg, const struct oe_env *env)
{

	cfg->endpoint = env->endpoint != NULL ? env->endpoint :
	    OE_DEFAULT_ENDPOINT;
	cfg->timeout = env->timeout_ms > 0 ?
	    (double)env->timeout_ms / 1000.0 : 0;
	cfg->headers = env->headers;
	cfg->nheaders = env->nheaders;
	cfg->compression = env->compression;
	cfg->spool_path = env->spool_path;
	cfg->spool_max = env->spool_max;
	cfg->spool_optional = env->spool_optional;
}

const char *
oe_severity_text(int severity, char *buf, size_t len)
{
	static const char *const names[] = { "TRACE", "DEBUG", "INFO",
	    "WARN", "ERROR", "FATAL" };
	int range;

	if (severity < OE_SEV_TRACE || severity > OE_SEV_FATAL + 3)
		severity = OE_SEV_INFO;
	range = (severity - 1) / 4;
	if ((severity - 1) % 4 == 0)
		snprintf(buf, len, "%s", names[range]);
	else
		snprintf(buf, len, "%s%d", names[range],
		    (severity - 1) % 4 + 1);
	return (buf);
}

void
oe_host_name(char *buf, size_t len)
{

	if (gethostname(buf, len) != 0)
		strlcpy(buf, "localhost", len);
	buf[len - 1] = '\0';
}

void
oe_host_arch(char *buf, size_t len)
{
	struct utsname uts;

	if (uname(&uts) == 0)
		strlcpy(buf, uts.machine, len);
	else
		strlcpy(buf, "", len);
}

void
oe_os_version(char *buf, size_t len)
{
	struct utsname uts;

	if (uname(&uts) == 0)
		strlcpy(buf, uts.release, len);
	else
		strlcpy(buf, "", len);
}

static void
sysctl_string(const char *name, char *buf, size_t len)
{
	size_t n = len;

	if (sysctlbyname(name, buf, &n, NULL, 0) != 0 || n == 0)
		buf[0] = '\0';
	buf[len - 1] = '\0';
}

/*
 * Machine architecture in the host.arch spelling of the semantic
 * conventions; architectures the convention does not list keep the
 * system's name.
 */
void
oe_host_arch_semconv(const char *machine_arch, char *buf, size_t len)
{
	static const struct {
		const char *sys, *otel;
	} map[] = {
		{ "amd64", "amd64" }, { "aarch64", "arm64" },
		{ "i386", "x86" }, { "powerpc64", "ppc64" },
		{ "powerpc64le", "ppc64" }, { "powerpc", "ppc32" },
		{ "armv6", "arm32" }, { "armv7", "arm32" },
	};
	size_t i;

	for (i = 0; i < nitems(map); i++)
		if (strcmp(machine_arch, map[i].sys) == 0) {
			strlcpy(buf, map[i].otel, len);
			return;
		}
	strlcpy(buf, machine_arch, len);
}

void
oe_host_detect(struct oe_host_info *hi)
{
	struct utsname uts;
	uint8_t u[16];
	char machine_arch[32], ident[64];

	memset(hi, 0, sizeof(*hi));
	oe_host_name(hi->host_name, sizeof(hi->host_name));
	sysctl_string("kern.hostuuid", hi->host_id, sizeof(hi->host_id));
	sysctl_string("hw.machine_arch", machine_arch, sizeof(machine_arch));
	oe_host_arch_semconv(machine_arch, hi->host_arch,
	    sizeof(hi->host_arch));
	strlcpy(hi->os_type, "freebsd", sizeof(hi->os_type));
	if (uname(&uts) == 0) {
		strlcpy(hi->os_name, uts.sysname, sizeof(hi->os_name));
		strlcpy(hi->os_version, uts.release, sizeof(hi->os_version));
	}
	/*
	 * "FreeBSD 16.0-CURRENT GENERIC": uname -v would also carry the
	 * build user, host and object path.
	 */
	sysctl_string("kern.ident", ident, sizeof(ident));
	snprintf(hi->os_description, sizeof(hi->os_description), "%s %s%s%s",
	    hi->os_name, hi->os_version, ident[0] != '\0' ? " " : "", ident);
	/* service.instance.id: a random (version 4) UUID per run. */
	arc4random_buf(u, sizeof(u));
	u[6] = (u[6] & 0x0f) | 0x40;
	u[8] = (u[8] & 0x3f) | 0x80;
	snprintf(hi->instance_id, sizeof(hi->instance_id),
	    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
	    "%02x%02x%02x%02x%02x%02x", u[0], u[1], u[2], u[3], u[4], u[5],
	    u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static const char *
nonempty(const char *s)
{

	return (s[0] != '\0' ? s : NULL);
}

void
oe_resource_host(struct oe_resource *r, const struct oe_host_info *hi)
{

	r->host_name = hi->host_name;
	r->host_arch = hi->host_arch;
	r->host_id = nonempty(hi->host_id);
	r->os_name = hi->os_type;
	r->os_full_name = nonempty(hi->os_name);
	r->os_version = hi->os_version;
	r->os_description = nonempty(hi->os_description);
	r->service_instance_id = hi->instance_id;
}

void
oe_frame_format(const struct oe_frame *f, char *buf, size_t len)
{

	if (f->module != NULL && f->symbol != NULL) {
		if (f->has_offset)
			snprintf(buf, len, "%s`%s+0x%jx", f->module,
			    f->symbol, (uintmax_t)f->offset);
		else
			snprintf(buf, len, "%s`%s", f->module, f->symbol);
	} else if (f->symbol != NULL)
		snprintf(buf, len, "%s", f->symbol);
	else
		snprintf(buf, len, "0x%016jx", (uintmax_t)f->addr);
}

void
oe_iso8601(const struct timespec *ts, char *buf, size_t len)
{
	struct tm tm;
	char date[32];

	/*
	 * Always UTC with a 'Z' suffix, matching the original Swift
	 * ISO8601DateFormatter output: timestamps stay lexically
	 * comparable across hosts regardless of their timezone.
	 */
	gmtime_r(&ts->tv_sec, &tm);
	strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(buf, len, "%s.%03ldZ", date, ts->tv_nsec / 1000000);
}
