/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared utilities: string buffer, JSON escaping, OTel environment
 * variables, host detection, frame and timestamp formatting.
 */

#include <sys/utsname.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "otelexport.h"

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

int
oe_buf_appendjson(struct oe_buf *b, const char *s)
{
	const char *p;
	char esc[8];

	if (s == NULL)
		return (0);
	for (p = s; *p != '\0'; p++) {
		unsigned char c = (unsigned char)*p;

		switch (c) {
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
			/*
			 * Escape control bytes AND everything >= 0x80:
			 * DTrace bodies and execnames are arbitrary
			 * bytes, and raw non-UTF-8 would make the whole
			 * document invalid JSON.  Latin-1-escaping is
			 * lossy for real UTF-8 text but always valid.
			 */
			if (c < 0x20 || c >= 0x80) {
				snprintf(esc, sizeof(esc), "\\u%04x", c);
				oe_buf_appendstr(b, esc);
			} else
				oe_buf_append(b, (const char *)p, 1);
			break;
		}
	}
	return (b->error ? -1 : 0);
}

/*
 * Parse a comma-separated key=value list into a malloc'd oe_attr
 * array.  Both keys and values are duplicated.
 */
static void
oe_parse_kvlist(const char *raw, struct oe_attr **attrsp, size_t *nattrsp)
{
	struct oe_attr *attrs;
	char *copy, *pair, *eq, *last;
	size_t n;

	*attrsp = NULL;
	*nattrsp = 0;
	if (raw == NULL || *raw == '\0')
		return;
	copy = strdup(raw);
	if (copy == NULL)
		return;
	attrs = NULL;
	n = 0;
	for (pair = strtok_r(copy, ",", &last); pair != NULL;
	    pair = strtok_r(NULL, ",", &last)) {
		eq = strchr(pair, '=');
		if (eq == NULL)
			continue;
		*eq = '\0';
		attrs = reallocf(attrs, (n + 1) * sizeof(*attrs));
		if (attrs == NULL) {
			free(copy);
			return;
		}
		attrs[n].name = strdup(pair);
		attrs[n].value = strdup(eq + 1);
		if (attrs[n].name == NULL || attrs[n].value == NULL) {
			free(__DECONST(char *, attrs[n].name));
			free(__DECONST(char *, attrs[n].value));
			break;
		}
		n++;
	}
	free(copy);
	*attrsp = attrs;
	*nattrsp = n;
}

void
oe_env_load(struct oe_env *env)
{
	const char *timeout;

	memset(env, 0, sizeof(*env));
	env->service_name = getenv("OTEL_SERVICE_NAME");
	env->endpoint = getenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	env->compression = getenv("OTEL_EXPORTER_OTLP_COMPRESSION");
	env->timeout_ms = -1;
	timeout = getenv("OTEL_EXPORTER_OTLP_TIMEOUT");
	if (timeout != NULL)
		env->timeout_ms = atoi(timeout);
	oe_parse_kvlist(getenv("OTEL_RESOURCE_ATTRIBUTES"),
	    &env->resource_attrs, &env->nresource_attrs);
	oe_parse_kvlist(getenv("OTEL_EXPORTER_OTLP_HEADERS"),
	    &env->headers, &env->nheaders);
}

void
oe_env_free(struct oe_env *env)
{
	size_t i;

	for (i = 0; i < env->nresource_attrs; i++) {
		free(__DECONST(char *, env->resource_attrs[i].name));
		free(__DECONST(char *, env->resource_attrs[i].value));
	}
	free(env->resource_attrs);
	for (i = 0; i < env->nheaders; i++) {
		free(__DECONST(char *, env->headers[i].name));
		free(__DECONST(char *, env->headers[i].value));
	}
	free(env->headers);
	memset(env, 0, sizeof(*env));
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
