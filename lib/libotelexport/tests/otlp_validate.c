/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Independent OTLP protobuf-JSON validator (see otlp_validate.h).
 *
 * The JSON parser is strict RFC 8259: no trailing commas, no raw
 * control characters, valid escapes, valid UTF-8 and UTF-16 pairs,
 * no duplicate object keys, the number grammar exactly.  The schema
 * tables transcribe opentelemetry/proto/{common,resource,logs,
 * metrics,trace}/v1 protos and the collector service requests.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "otlp_validate.h"

#define	JV_MAX_DEPTH	64

/* ---------------------------------------------------------------- */
/* JSON parser							 	*/

struct parser {
	const char	*p, *end;
	char		*err;
	size_t		 errlen;
	int		 depth;
};

static void
perr(struct parser *ps, const char *fmt, ...)
{
	va_list ap;
	char msg[200];

	if (ps->err[0] != '\0')
		return;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	snprintf(ps->err, ps->errlen, "json: %s", msg);
}

static void
skip_ws(struct parser *ps)
{

	while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' ||
	    *ps->p == '\n' || *ps->p == '\r'))
		ps->p++;
}

static struct jv *
jv_new(enum jv_type t)
{
	struct jv *v;

	v = calloc(1, sizeof(*v));
	if (v != NULL)
		v->type = t;
	return (v);
}

void
jv_free(struct jv *v)
{
	size_t i;

	if (v == NULL)
		return;
	for (i = 0; i < v->n; i++) {
		jv_free(v->items[i]);
		if (v->keys != NULL)
			free(v->keys[i]);
	}
	free(v->items);
	free(v->keys);
	free(v->s);
	free(v);
}

static int
put_utf8(char *out, size_t *o, uint32_t cp)
{

	if (cp < 0x80)
		out[(*o)++] = (char)cp;
	else if (cp < 0x800) {
		out[(*o)++] = (char)(0xc0 | (cp >> 6));
		out[(*o)++] = (char)(0x80 | (cp & 0x3f));
	} else if (cp < 0x10000) {
		out[(*o)++] = (char)(0xe0 | (cp >> 12));
		out[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
		out[(*o)++] = (char)(0x80 | (cp & 0x3f));
	} else {
		out[(*o)++] = (char)(0xf0 | (cp >> 18));
		out[(*o)++] = (char)(0x80 | ((cp >> 12) & 0x3f));
		out[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
		out[(*o)++] = (char)(0x80 | (cp & 0x3f));
	}
	return (0);
}

static int
hex4(const char *s, uint32_t *v)
{
	int i;

	*v = 0;
	for (i = 0; i < 4; i++) {
		if (!isxdigit((unsigned char)s[i]))
			return (-1);
		*v = *v * 16 + (uint32_t)(isdigit((unsigned char)s[i]) ?
		    s[i] - '0' : (tolower((unsigned char)s[i]) - 'a' + 10));
	}
	return (0);
}

/* Length of a valid UTF-8 sequence at s, or 0. */
static size_t
utf8_len(const unsigned char *s, const unsigned char *end)
{
	size_t n, i;
	uint32_t cp;

	if (s[0] < 0x80)
		return (1);
	if ((s[0] & 0xe0) == 0xc0) {
		n = 2;
		cp = s[0] & 0x1f;
	} else if ((s[0] & 0xf0) == 0xe0) {
		n = 3;
		cp = s[0] & 0x0f;
	} else if ((s[0] & 0xf8) == 0xf0) {
		n = 4;
		cp = s[0] & 0x07;
	} else
		return (0);
	if ((size_t)(end - s) < n)
		return (0);
	for (i = 1; i < n; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return (0);
		cp = (cp << 6) | (s[i] & 0x3f);
	}
	/* Overlong, surrogate, or out of range. */
	if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) ||
	    (n == 4 && cp < 0x10000) || cp > 0x10ffff ||
	    (cp >= 0xd800 && cp <= 0xdfff))
		return (0);
	return (n);
}

static char *
parse_string_raw(struct parser *ps, size_t *lenp)
{
	char *out;
	size_t o, n;
	uint32_t cp, lo;

	ps->p++;	/* opening quote */
	out = malloc((size_t)(ps->end - ps->p) + 1);
	if (out == NULL) {
		perr(ps, "out of memory");
		return (NULL);
	}
	o = 0;
	while (ps->p < ps->end && *ps->p != '"') {
		unsigned char c = (unsigned char)*ps->p;

		if (c < 0x20) {
			perr(ps, "raw control character 0x%02x in string", c);
			goto bad;
		}
		if (c != '\\') {
			n = utf8_len((const unsigned char *)ps->p,
			    (const unsigned char *)ps->end);
			if (n == 0) {
				perr(ps, "invalid UTF-8 in string");
				goto bad;
			}
			memcpy(out + o, ps->p, n);
			o += n;
			ps->p += n;
			continue;
		}
		if (ps->end - ps->p < 2) {
			perr(ps, "truncated escape");
			goto bad;
		}
		switch (ps->p[1]) {
		case '"': out[o++] = '"'; break;
		case '\\': out[o++] = '\\'; break;
		case '/': out[o++] = '/'; break;
		case 'b': out[o++] = '\b'; break;
		case 'f': out[o++] = '\f'; break;
		case 'n': out[o++] = '\n'; break;
		case 'r': out[o++] = '\r'; break;
		case 't': out[o++] = '\t'; break;
		case 'u':
			if (ps->end - ps->p < 6 || hex4(ps->p + 2, &cp) != 0) {
				perr(ps, "bad \\u escape");
				goto bad;
			}
			ps->p += 4;
			if (cp >= 0xdc00 && cp <= 0xdfff) {
				perr(ps, "lone low surrogate");
				goto bad;
			}
			if (cp >= 0xd800 && cp <= 0xdbff) {
				if (ps->end - ps->p < 8 || ps->p[2] != '\\' ||
				    ps->p[3] != 'u' ||
				    hex4(ps->p + 4, &lo) != 0 ||
				    lo < 0xdc00 || lo > 0xdfff) {
					perr(ps, "unpaired high surrogate");
					goto bad;
				}
				cp = 0x10000 + ((cp - 0xd800) << 10) +
				    (lo - 0xdc00);
				ps->p += 6;
			}
			put_utf8(out, &o, cp);
			break;
		default:
			perr(ps, "invalid escape \\%c", ps->p[1]);
			goto bad;
		}
		ps->p += 2;
	}
	if (ps->p >= ps->end) {
		perr(ps, "unterminated string");
		goto bad;
	}
	ps->p++;
	out[o] = '\0';
	*lenp = o;
	return (out);
bad:
	free(out);
	return (NULL);
}

static struct jv *parse_value(struct parser *);

static int
push(struct jv *v, char *key, struct jv *item)
{
	struct jv **ni;
	char **nk;

	ni = realloc(v->items, (v->n + 1) * sizeof(*ni));
	if (ni == NULL)
		return (-1);
	v->items = ni;
	if (v->type == JV_OBJ) {
		nk = realloc(v->keys, (v->n + 1) * sizeof(*nk));
		if (nk == NULL)
			return (-1);
		v->keys = nk;
		v->keys[v->n] = key;
	}
	v->items[v->n++] = item;
	return (0);
}

static struct jv *
parse_container(struct parser *ps, int is_obj)
{
	struct jv *v, *item;
	char *key;
	size_t klen, i;

	if (++ps->depth > JV_MAX_DEPTH) {
		perr(ps, "nesting too deep");
		return (NULL);
	}
	v = jv_new(is_obj ? JV_OBJ : JV_ARR);
	if (v == NULL)
		return (NULL);
	ps->p++;
	skip_ws(ps);
	if (ps->p < ps->end && *ps->p == (is_obj ? '}' : ']')) {
		ps->p++;
		ps->depth--;
		return (v);
	}
	for (;;) {
		key = NULL;
		skip_ws(ps);
		if (is_obj) {
			if (ps->p >= ps->end || *ps->p != '"') {
				perr(ps, "expected object key");
				goto bad;
			}
			key = parse_string_raw(ps, &klen);
			if (key == NULL)
				goto bad;
			for (i = 0; i < v->n; i++)
				if (strcmp(v->keys[i], key) == 0) {
					perr(ps, "duplicate key \"%s\"", key);
					free(key);
					goto bad;
				}
			skip_ws(ps);
			if (ps->p >= ps->end || *ps->p != ':') {
				perr(ps, "expected ':' after key");
				free(key);
				goto bad;
			}
			ps->p++;
		}
		item = parse_value(ps);
		if (item == NULL || push(v, key, item) != 0) {
			jv_free(item);
			free(key);
			goto bad;
		}
		skip_ws(ps);
		if (ps->p < ps->end && *ps->p == ',') {
			ps->p++;
			skip_ws(ps);
			if (ps->p < ps->end &&
			    (*ps->p == ']' || *ps->p == '}')) {
				perr(ps, "trailing comma");
				goto bad;
			}
			continue;
		}
		if (ps->p < ps->end && *ps->p == (is_obj ? '}' : ']')) {
			ps->p++;
			break;
		}
		perr(ps, "expected ',' or '%c'", is_obj ? '}' : ']');
		goto bad;
	}
	ps->depth--;
	return (v);
bad:
	jv_free(v);
	return (NULL);
}

static struct jv *
parse_number(struct parser *ps)
{
	const char *start = ps->p;
	struct jv *v;

	if (ps->p < ps->end && *ps->p == '-')
		ps->p++;
	if (ps->p >= ps->end || !isdigit((unsigned char)*ps->p)) {
		perr(ps, "bad number");
		return (NULL);
	}
	if (*ps->p == '0' && ps->p + 1 < ps->end &&
	    isdigit((unsigned char)ps->p[1])) {
		perr(ps, "leading zero in number");
		return (NULL);
	}
	while (ps->p < ps->end && isdigit((unsigned char)*ps->p))
		ps->p++;
	if (ps->p < ps->end && *ps->p == '.') {
		ps->p++;
		if (ps->p >= ps->end || !isdigit((unsigned char)*ps->p)) {
			perr(ps, "bad fraction");
			return (NULL);
		}
		while (ps->p < ps->end && isdigit((unsigned char)*ps->p))
			ps->p++;
	}
	if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
		ps->p++;
		if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-'))
			ps->p++;
		if (ps->p >= ps->end || !isdigit((unsigned char)*ps->p)) {
			perr(ps, "bad exponent");
			return (NULL);
		}
		while (ps->p < ps->end && isdigit((unsigned char)*ps->p))
			ps->p++;
	}
	v = jv_new(JV_NUM);
	if (v != NULL) {
		v->s = strndup(start, (size_t)(ps->p - start));
		v->slen = (size_t)(ps->p - start);
	}
	return (v);
}

static int
literal(struct parser *ps, const char *word)
{
	size_t n = strlen(word);

	if ((size_t)(ps->end - ps->p) >= n && memcmp(ps->p, word, n) == 0) {
		ps->p += n;
		return (1);
	}
	return (0);
}

static struct jv *
parse_value(struct parser *ps)
{
	struct jv *v;

	skip_ws(ps);
	if (ps->p >= ps->end) {
		perr(ps, "unexpected end of input");
		return (NULL);
	}
	switch (*ps->p) {
	case '{':
		return (parse_container(ps, 1));
	case '[':
		return (parse_container(ps, 0));
	case '"':
		v = jv_new(JV_STR);
		if (v != NULL && (v->s = parse_string_raw(ps,
		    &v->slen)) == NULL) {
			jv_free(v);
			v = NULL;
		}
		return (v);
	case 't':
	case 'f':
		if (literal(ps, "true") || literal(ps, "false")) {
			v = jv_new(JV_BOOL);
			if (v != NULL)
				v->b = ps->p[-1] == 'e' && ps->p[-2] == 'u';
			return (v);
		}
		break;
	case 'n':
		if (literal(ps, "null"))
			return (jv_new(JV_NULL));
		break;
	default:
		return (parse_number(ps));
	}
	perr(ps, "invalid literal");
	return (NULL);
}

struct jv *
jv_parse(const char *text, size_t len, char *err, size_t errlen)
{
	struct parser ps;
	struct jv *v;

	err[0] = '\0';
	ps.p = text;
	ps.end = text + len;
	ps.err = err;
	ps.errlen = errlen;
	ps.depth = 0;
	v = parse_value(&ps);
	if (v == NULL) {
		if (err[0] == '\0')
			snprintf(err, errlen, "json: out of memory");
		return (NULL);
	}
	skip_ws(&ps);
	if (ps.p != ps.end) {
		snprintf(err, errlen, "json: trailing data after value");
		jv_free(v);
		return (NULL);
	}
	return (v);
}

const struct jv *
jv_get(const struct jv *obj, const char *key)
{
	size_t i;

	if (obj == NULL || obj->type != JV_OBJ)
		return (NULL);
	for (i = 0; i < obj->n; i++)
		if (strcmp(obj->keys[i], key) == 0)
			return (obj->items[i]);
	return (NULL);
}

/* ---------------------------------------------------------------- */
/* OTLP schema							 	*/

enum fkind {
	F_STRING, F_BOOL, F_U32, F_ENUM, F_I64, F_U64, F_DOUBLE,
	F_TRACEID, F_SPANID, F_BYTES, F_MSG, F_ANY
};

struct msgdesc;

struct fielddesc {
	const char	*name;
	enum fkind	 kind;
	int		 repeated;
	const struct msgdesc *msg;
	int		 enum_max;	/* F_ENUM: valid 0..enum_max */
	const char	*oneof;		/* oneof group name or NULL */
};

struct msgdesc {
	const char	*name;
	const struct fielddesc *fields;
	int		(*check)(const struct jv *, const char *path,
			    struct otlp_counts *, char *, size_t);
};

#define	FLD(n, k)		{ n, k, 0, NULL, 0, NULL }
#define	REP(n, k)		{ n, k, 1, NULL, 0, NULL }
#define	MSG(n, m)		{ n, F_MSG, 0, &m, 0, NULL }
#define	REPMSG(n, m)		{ n, F_MSG, 1, &m, 0, NULL }
#define	ENUMF(n, max)		{ n, F_ENUM, 0, NULL, max, NULL }
#define	ONEOF(n, k, g)		{ n, k, 0, NULL, 0, g }
#define	ONEOFMSG(n, m, g)	{ n, F_MSG, 0, &m, 0, g }
#define	END			{ NULL, 0, 0, NULL, 0, NULL }

static const struct msgdesc KeyValue, AnyArray, KeyValueList, Resource,
    Scope, LogRecord, ScopeLogs, ResourceLogs, LogsReq, NumberDP, HistDP,
    Gauge, Sum, Histogram, Metric, ScopeMetrics, ResourceMetrics,
    MetricsReq, SpanEvent, SpanLink, Status, Span, ScopeSpans,
    ResourceSpans, TracesReq, EntityRef;

static int check_keyvalue_list(const struct jv *, const char *, char *,
    size_t);
static int check_metric(const struct jv *, const char *,
    struct otlp_counts *, char *, size_t);
static int check_histdp(const struct jv *, const char *,
    struct otlp_counts *, char *, size_t);
static int check_numberdp(const struct jv *, const char *,
    struct otlp_counts *, char *, size_t);
static int check_span(const struct jv *, const char *,
    struct otlp_counts *, char *, size_t);
static int count_log(const struct jv *, const char *,
    struct otlp_counts *, char *, size_t);
static int check_attr_holder(const struct jv *, const char *,
    struct otlp_counts *, char *, size_t);

static const struct fielddesc kv_fields[] = {
	FLD("key", F_STRING), FLD("value", F_ANY), END };
static const struct msgdesc KeyValue = { "KeyValue", kv_fields, NULL };

static const struct fielddesc arr_fields[] = { REP("values", F_ANY), END };
static const struct msgdesc AnyArray = { "ArrayValue", arr_fields, NULL };

static const struct fielddesc kvl_fields[] = {
	REPMSG("values", KeyValue), END };
static const struct msgdesc KeyValueList = { "KeyValueList", kvl_fields,
    check_attr_holder };

static const struct fielddesc entref_fields[] = {
	FLD("schemaUrl", F_STRING), FLD("type", F_STRING),
	REP("idKeys", F_STRING), REP("descriptionKeys", F_STRING), END };
static const struct msgdesc EntityRef = { "EntityRef", entref_fields,
    NULL };

static const struct fielddesc res_fields[] = {
	REPMSG("attributes", KeyValue), FLD("droppedAttributesCount", F_U32),
	REPMSG("entityRefs", EntityRef), END };
static const struct msgdesc Resource = { "Resource", res_fields,
    check_attr_holder };

static const struct fielddesc scope_fields[] = {
	FLD("name", F_STRING), FLD("version", F_STRING),
	REPMSG("attributes", KeyValue), FLD("droppedAttributesCount", F_U32),
	END };
static const struct msgdesc Scope = { "InstrumentationScope", scope_fields,
    check_attr_holder };

static const struct fielddesc log_fields[] = {
	FLD("timeUnixNano", F_U64), FLD("observedTimeUnixNano", F_U64),
	ENUMF("severityNumber", 24), FLD("severityText", F_STRING),
	FLD("body", F_ANY), REPMSG("attributes", KeyValue),
	FLD("droppedAttributesCount", F_U32), FLD("flags", F_U32),
	FLD("traceId", F_TRACEID), FLD("spanId", F_SPANID),
	FLD("eventName", F_STRING), END };
static const struct msgdesc LogRecord = { "LogRecord", log_fields,
    count_log };

static const struct fielddesc slogs_fields[] = {
	MSG("scope", Scope), REPMSG("logRecords", LogRecord),
	FLD("schemaUrl", F_STRING), END };
static const struct msgdesc ScopeLogs = { "ScopeLogs", slogs_fields, NULL };

static const struct fielddesc rlogs_fields[] = {
	MSG("resource", Resource), REPMSG("scopeLogs", ScopeLogs),
	FLD("schemaUrl", F_STRING), END };
static const struct msgdesc ResourceLogs = { "ResourceLogs", rlogs_fields,
    NULL };

static const struct fielddesc logsreq_fields[] = {
	REPMSG("resourceLogs", ResourceLogs), END };
static const struct msgdesc LogsReq = { "ExportLogsServiceRequest",
    logsreq_fields, NULL };

static const struct fielddesc ndp_fields[] = {
	REPMSG("attributes", KeyValue), FLD("startTimeUnixNano", F_U64),
	FLD("timeUnixNano", F_U64), ONEOF("asDouble", F_DOUBLE, "value"),
	ONEOF("asInt", F_I64, "value"), FLD("flags", F_U32), END };
static const struct msgdesc NumberDP = { "NumberDataPoint", ndp_fields,
    check_numberdp };

static const struct fielddesc hdp_fields[] = {
	REPMSG("attributes", KeyValue), FLD("startTimeUnixNano", F_U64),
	FLD("timeUnixNano", F_U64), FLD("count", F_U64),
	FLD("sum", F_DOUBLE), REP("bucketCounts", F_U64),
	REP("explicitBounds", F_DOUBLE), FLD("flags", F_U32),
	FLD("min", F_DOUBLE), FLD("max", F_DOUBLE), END };
static const struct msgdesc HistDP = { "HistogramDataPoint", hdp_fields,
    check_histdp };

static const struct fielddesc gauge_fields[] = {
	REPMSG("dataPoints", NumberDP), END };
static const struct msgdesc Gauge = { "Gauge", gauge_fields, NULL };

static const struct fielddesc sum_fields[] = {
	REPMSG("dataPoints", NumberDP), ENUMF("aggregationTemporality", 2),
	FLD("isMonotonic", F_BOOL), END };
static const struct msgdesc Sum = { "Sum", sum_fields, NULL };

static const struct fielddesc hist_fields[] = {
	REPMSG("dataPoints", HistDP), ENUMF("aggregationTemporality", 2),
	END };
static const struct msgdesc Histogram = { "Histogram", hist_fields, NULL };

static const struct fielddesc metric_fields[] = {
	FLD("name", F_STRING), FLD("description", F_STRING),
	FLD("unit", F_STRING), REPMSG("metadata", KeyValue),
	ONEOFMSG("gauge", Gauge, "data"), ONEOFMSG("sum", Sum, "data"),
	ONEOFMSG("histogram", Histogram, "data"), END };
static const struct msgdesc Metric = { "Metric", metric_fields,
    check_metric };

static int check_scope_metrics(const struct jv *, const char *,
    struct otlp_counts *, char *, size_t);

static const struct fielddesc smet_fields[] = {
	MSG("scope", Scope), REPMSG("metrics", Metric),
	FLD("schemaUrl", F_STRING), END };
static const struct msgdesc ScopeMetrics = { "ScopeMetrics", smet_fields,
    check_scope_metrics };

static const struct fielddesc rmet_fields[] = {
	MSG("resource", Resource), REPMSG("scopeMetrics", ScopeMetrics),
	FLD("schemaUrl", F_STRING), END };
static const struct msgdesc ResourceMetrics = { "ResourceMetrics",
    rmet_fields, NULL };

static const struct fielddesc metreq_fields[] = {
	REPMSG("resourceMetrics", ResourceMetrics), END };
static const struct msgdesc MetricsReq = { "ExportMetricsServiceRequest",
    metreq_fields, NULL };

static const struct fielddesc ev_fields[] = {
	FLD("timeUnixNano", F_U64), FLD("name", F_STRING),
	REPMSG("attributes", KeyValue), FLD("droppedAttributesCount", F_U32),
	END };
static const struct msgdesc SpanEvent = { "Span.Event", ev_fields,
    check_attr_holder };

static const struct fielddesc link_fields[] = {
	FLD("traceId", F_TRACEID), FLD("spanId", F_SPANID),
	FLD("traceState", F_STRING), REPMSG("attributes", KeyValue),
	FLD("droppedAttributesCount", F_U32), FLD("flags", F_U32), END };
static const struct msgdesc SpanLink = { "Span.Link", link_fields,
    check_attr_holder };

static const struct fielddesc status_fields[] = {
	FLD("message", F_STRING), ENUMF("code", 2), END };
static const struct msgdesc Status = { "Status", status_fields, NULL };

static const struct fielddesc span_fields[] = {
	FLD("traceId", F_TRACEID), FLD("spanId", F_SPANID),
	FLD("traceState", F_STRING), FLD("parentSpanId", F_SPANID),
	FLD("flags", F_U32), FLD("name", F_STRING), ENUMF("kind", 5),
	FLD("startTimeUnixNano", F_U64), FLD("endTimeUnixNano", F_U64),
	REPMSG("attributes", KeyValue), FLD("droppedAttributesCount", F_U32),
	REPMSG("events", SpanEvent), FLD("droppedEventsCount", F_U32),
	REPMSG("links", SpanLink), FLD("droppedLinksCount", F_U32),
	MSG("status", Status), END };
static const struct msgdesc Span = { "Span", span_fields, check_span };

static const struct fielddesc sspans_fields[] = {
	MSG("scope", Scope), REPMSG("spans", Span),
	FLD("schemaUrl", F_STRING), END };
static const struct msgdesc ScopeSpans = { "ScopeSpans", sspans_fields,
    NULL };

static const struct fielddesc rspans_fields[] = {
	MSG("resource", Resource), REPMSG("scopeSpans", ScopeSpans),
	FLD("schemaUrl", F_STRING), END };
static const struct msgdesc ResourceSpans = { "ResourceSpans",
    rspans_fields, NULL };

static const struct fielddesc trreq_fields[] = {
	REPMSG("resourceSpans", ResourceSpans), END };
static const struct msgdesc TracesReq = { "ExportTraceServiceRequest",
    trreq_fields, NULL };

static int
verr(char *err, size_t errlen, const char *path, const char *fmt, ...)
{
	va_list ap;
	char msg[200];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	snprintf(err, errlen, "%s: %s", path, msg);
	return (-1);
}

/* Decimal integer string within [lo, hi] (as signed or unsigned). */
static int
int_string_ok(const char *s, int is_signed)
{
	const char *p = s;
	char *end;

	if (*p == '-') {
		if (!is_signed)
			return (0);
		p++;
	}
	if (!isdigit((unsigned char)*p) || (p[0] == '0' && p[1] != '\0'))
		return (0);
	for (; *p != '\0'; p++)
		if (!isdigit((unsigned char)*p))
			return (0);
	errno = 0;
	if (is_signed)
		(void)strtoimax(s, &end, 10);
	else
		(void)strtoumax(s, &end, 10);
	return (errno == 0);
}

static int
hex_id_ok(const char *s, size_t want)
{
	size_t i;
	int nonzero = 0;

	if (strlen(s) != want)
		return (0);
	for (i = 0; i < want; i++) {
		if (!isdigit((unsigned char)s[i]) &&
		    (s[i] < 'a' || s[i] > 'f'))
			return (0);
		if (s[i] != '0')
			nonzero = 1;
	}
	return (nonzero);
}

static int
base64_ok(const char *s)
{
	size_t n = strlen(s), i;

	if (n % 4 != 0)
		return (0);
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '+' &&
		    s[i] != '/' && !(s[i] == '=' && i >= n - 2))
			return (0);
	return (1);
}

static int validate_msg(const struct jv *, const struct msgdesc *,
    const char *, struct otlp_counts *, char *, size_t);

static int
validate_any(const struct jv *v, const char *path, char *err, size_t errlen)
{
	static const char *const kinds[] = { "stringValue", "boolValue",
	    "intValue", "doubleValue", "arrayValue", "kvlistValue",
	    "bytesValue" };
	const struct jv *x;
	char sub[512];
	size_t found;

	if (v->type != JV_OBJ)
		return (verr(err, errlen, path, "AnyValue must be an object"));
	/* An empty AnyValue is legal (unset); more than one is not. */
	if (v->n > 1)
		return (verr(err, errlen, path, "AnyValue has %zu values",
		    v->n));
	if (v->n == 0)
		return (0);
	for (found = 0; found < nitems(kinds); found++)
		if (strcmp(v->keys[0], kinds[found]) == 0)
			break;
	snprintf(sub, sizeof(sub), "%s.%s", path, v->keys[0]);
	x = v->items[0];
	switch (found) {
	case 0:
		if (x->type != JV_STR)
			return (verr(err, errlen, sub, "expected string"));
		return (0);
	case 1:
		if (x->type != JV_BOOL)
			return (verr(err, errlen, sub, "expected bool"));
		return (0);
	case 2:
		if (x->type != JV_STR || !int_string_ok(x->s, 1))
			return (verr(err, errlen, sub,
			    "int64 must be a decimal string"));
		return (0);
	case 3:
		if (x->type != JV_NUM && !(x->type == JV_STR &&
		    (strcmp(x->s, "NaN") == 0 ||
		    strcmp(x->s, "Infinity") == 0 ||
		    strcmp(x->s, "-Infinity") == 0)))
			return (verr(err, errlen, sub, "expected double"));
		return (0);
	case 4:
		return (validate_msg(x, &AnyArray, sub, NULL, err, errlen));
	case 5:
		return (validate_msg(x, &KeyValueList, sub, NULL, err,
		    errlen));
	case 6:
		if (x->type != JV_STR || !base64_ok(x->s))
			return (verr(err, errlen, sub,
			    "bytes must be base64"));
		return (0);
	}
	return (verr(err, errlen, path, "unknown AnyValue field \"%s\"",
	    v->keys[0]));
}

static int
validate_scalar(const struct jv *x, const struct fielddesc *f,
    const char *path, struct otlp_counts *c, char *err, size_t errlen)
{
	char *end;
	long long n;

	switch (f->kind) {
	case F_STRING:
		if (x->type != JV_STR)
			return (verr(err, errlen, path, "expected string"));
		return (0);
	case F_BOOL:
		if (x->type != JV_BOOL)
			return (verr(err, errlen, path, "expected bool"));
		return (0);
	case F_U32:
	case F_ENUM:
		/* Enums are written as integers by this pipeline. */
		if (x->type != JV_NUM || strpbrk(x->s, ".eE-") != NULL)
			return (verr(err, errlen, path,
			    "expected a non-negative integer number"));
		errno = 0;
		n = strtoll(x->s, &end, 10);
		if (errno != 0 || n > (f->kind == F_ENUM ? f->enum_max :
		    0xffffffffLL))
			return (verr(err, errlen, path, "value %s out of "
			    "range", x->s));
		return (0);
	case F_I64:
	case F_U64:
		if (x->type != JV_STR || !int_string_ok(x->s,
		    f->kind == F_I64))
			return (verr(err, errlen, path, "64-bit integer must "
			    "be a decimal string, got %s",
			    x->type == JV_STR ? x->s : "non-string"));
		return (0);
	case F_DOUBLE:
		if (x->type != JV_NUM && !(x->type == JV_STR &&
		    (strcmp(x->s, "NaN") == 0 ||
		    strcmp(x->s, "Infinity") == 0 ||
		    strcmp(x->s, "-Infinity") == 0)))
			return (verr(err, errlen, path, "expected double"));
		return (0);
	case F_TRACEID:
	case F_SPANID:
		/* OTLP JSON: ids are hex, not base64; "" means unset. */
		if (x->type != JV_STR || (x->s[0] != '\0' &&
		    !hex_id_ok(x->s, f->kind == F_TRACEID ? 32 : 16)))
			return (verr(err, errlen, path, "%s must be %d "
			    "lowercase hex digits, non-zero",
			    f->kind == F_TRACEID ? "trace id" : "span id",
			    f->kind == F_TRACEID ? 32 : 16));
		return (0);
	case F_BYTES:
		if (x->type != JV_STR || !base64_ok(x->s))
			return (verr(err, errlen, path, "bytes must be "
			    "base64"));
		return (0);
	case F_ANY:
		return (validate_any(x, path, err, errlen));
	case F_MSG:
		return (validate_msg(x, f->msg, path, c, err, errlen));
	}
	return (verr(err, errlen, path, "internal: bad field kind"));
}

static int
validate_msg(const struct jv *v, const struct msgdesc *m, const char *path,
    struct otlp_counts *c, char *err, size_t errlen)
{
	const struct fielddesc *f;
	const char *oneof_seen[4];
	char sub[512];
	size_t i, j, k, noneof;

	if (v->type != JV_OBJ)
		return (verr(err, errlen, path, "%s must be an object",
		    m->name));
	noneof = 0;
	for (i = 0; i < v->n; i++) {
		for (f = m->fields; f->name != NULL; f++)
			if (strcmp(f->name, v->keys[i]) == 0)
				break;
		if (f->name == NULL)
			return (verr(err, errlen, path, "unknown %s field "
			    "\"%s\"", m->name, v->keys[i]));
		if (f->oneof != NULL) {
			for (k = 0; k < noneof; k++)
				if (strcmp(oneof_seen[k], f->oneof) == 0)
					return (verr(err, errlen, path,
					    "more than one member of oneof "
					    "%s", f->oneof));
			if (noneof < nitems(oneof_seen))
				oneof_seen[noneof++] = f->oneof;
		}
		snprintf(sub, sizeof(sub), "%s.%s", path, f->name);
		if (f->repeated) {
			if (v->items[i]->type != JV_ARR)
				return (verr(err, errlen, sub,
				    "repeated field must be an array"));
			for (j = 0; j < v->items[i]->n; j++) {
				char el[540];

				snprintf(el, sizeof(el), "%s[%zu]", sub, j);
				if (validate_scalar(v->items[i]->items[j], f,
				    el, c, err, errlen) != 0)
					return (-1);
			}
		} else if (validate_scalar(v->items[i], f, sub, c, err,
		    errlen) != 0)
			return (-1);
	}
	if (m->check != NULL)
		return (m->check(v, path, c, err, errlen));
	return (0);
}

/* Attribute keys must be non-empty and unique within one list. */
static int
check_keyvalue_list(const struct jv *arr, const char *path, char *err,
    size_t errlen)
{
	const struct jv *ki, *kj;
	size_t i, j;

	if (arr == NULL)
		return (0);
	for (i = 0; i < arr->n; i++) {
		ki = jv_get(arr->items[i], "key");
		if (ki == NULL || ki->s[0] == '\0')
			return (verr(err, errlen, path,
			    "attribute [%zu] has no key", i));
		if (jv_get(arr->items[i], "value") == NULL)
			return (verr(err, errlen, path,
			    "attribute \"%s\" has no value", ki->s));
		for (j = 0; j < i; j++) {
			kj = jv_get(arr->items[j], "key");
			if (strcmp(ki->s, kj->s) == 0)
				return (verr(err, errlen, path,
				    "duplicate attribute key \"%s\"", ki->s));
		}
	}
	return (0);
}

static int
check_attr_holder(const struct jv *v, const char *path,
    struct otlp_counts *c, char *err, size_t errlen)
{

	(void)c;
	return (check_keyvalue_list(jv_get(v, "attributes") != NULL ?
	    jv_get(v, "attributes") : jv_get(v, "values"), path, err,
	    errlen));
}

static int
count_log(const struct jv *v, const char *path, struct otlp_counts *c,
    char *err, size_t errlen)
{

	if (c != NULL)
		c->logs++;
	return (check_attr_holder(v, path, c, err, errlen));
}

static int
check_numberdp(const struct jv *v, const char *path, struct otlp_counts *c,
    char *err, size_t errlen)
{

	if (jv_get(v, "asInt") == NULL && jv_get(v, "asDouble") == NULL)
		return (verr(err, errlen, path, "data point has no value"));
	if (jv_get(v, "timeUnixNano") == NULL)
		return (verr(err, errlen, path, "data point has no time"));
	if (c != NULL)
		c->datapoints++;
	return (check_attr_holder(v, path, c, err, errlen));
}

static int
check_histdp(const struct jv *v, const char *path, struct otlp_counts *c,
    char *err, size_t errlen)
{
	const struct jv *counts, *bounds, *count;
	unsigned long long total;
	double prev, cur;
	size_t i;

	counts = jv_get(v, "bucketCounts");
	bounds = jv_get(v, "explicitBounds");
	count = jv_get(v, "count");
	if (jv_get(v, "timeUnixNano") == NULL)
		return (verr(err, errlen, path, "data point has no time"));
	if (counts != NULL && counts->n > 0 &&
	    counts->n != (bounds != NULL ? bounds->n : 0) + 1)
		return (verr(err, errlen, path, "%zu bucketCounts need %zu "
		    "explicitBounds", counts->n, counts->n - 1));
	for (i = 0; bounds != NULL && i < bounds->n; i++) {
		cur = strtod(bounds->items[i]->s, NULL);
		if (i > 0 && !(cur > prev))
			return (verr(err, errlen, path, "explicitBounds not "
			    "strictly increasing at [%zu]", i));
		prev = cur;
	}
	total = 0;
	for (i = 0; counts != NULL && i < counts->n; i++)
		total += strtoull(counts->items[i]->s, NULL, 10);
	if (counts != NULL && counts->n > 0 && (count == NULL ||
	    strtoull(count->s, NULL, 10) != total))
		return (verr(err, errlen, path, "count %s != sum of "
		    "bucketCounts %llu", count != NULL ? count->s : "(none)",
		    total));
	if (c != NULL)
		c->datapoints++;
	return (check_attr_holder(v, path, c, err, errlen));
}

static int
check_metric(const struct jv *v, const char *path, struct otlp_counts *c,
    char *err, size_t errlen)
{
	const struct jv *name;

	name = jv_get(v, "name");
	if (name == NULL || name->s[0] == '\0')
		return (verr(err, errlen, path, "metric has no name"));
	if (jv_get(v, "gauge") == NULL && jv_get(v, "sum") == NULL &&
	    jv_get(v, "histogram") == NULL)
		return (verr(err, errlen, path, "metric \"%s\" has no data",
		    name->s));
	if (c != NULL)
		c->metrics++;
	return (0);
}

static const char *
metric_type(const struct jv *m)
{

	if (jv_get(m, "gauge") != NULL)
		return ("gauge");
	if (jv_get(m, "sum") != NULL)
		return ("sum");
	return ("histogram");
}

/*
 * The data model forbids one scope from carrying two metrics of the
 * same name with different types (an identity conflict).
 */
static int
check_scope_metrics(const struct jv *v, const char *path,
    struct otlp_counts *c, char *err, size_t errlen)
{
	const struct jv *ms, *ni, *nj;
	size_t i, j;

	(void)c;
	ms = jv_get(v, "metrics");
	for (i = 0; ms != NULL && i < ms->n; i++) {
		ni = jv_get(ms->items[i], "name");
		for (j = 0; j < i; j++) {
			nj = jv_get(ms->items[j], "name");
			if (strcmp(ni->s, nj->s) == 0 &&
			    strcmp(metric_type(ms->items[i]),
			    metric_type(ms->items[j])) != 0)
				return (verr(err, errlen, path, "metric \"%s\" "
				    "is both %s and %s", ni->s,
				    metric_type(ms->items[j]),
				    metric_type(ms->items[i])));
		}
	}
	return (0);
}

static int
check_span(const struct jv *v, const char *path, struct otlp_counts *c,
    char *err, size_t errlen)
{
	const struct jv *tid, *sid, *pid, *name, *st, *et;

	tid = jv_get(v, "traceId");
	sid = jv_get(v, "spanId");
	pid = jv_get(v, "parentSpanId");
	name = jv_get(v, "name");
	st = jv_get(v, "startTimeUnixNano");
	et = jv_get(v, "endTimeUnixNano");
	if (tid == NULL || tid->s[0] == '\0')
		return (verr(err, errlen, path, "span has no traceId"));
	if (sid == NULL || sid->s[0] == '\0')
		return (verr(err, errlen, path, "span has no spanId"));
	if (pid != NULL && strcmp(pid->s, sid->s) == 0)
		return (verr(err, errlen, path, "span is its own parent"));
	if (name == NULL || name->s[0] == '\0')
		return (verr(err, errlen, path, "span has no name"));
	if (st == NULL || et == NULL)
		return (verr(err, errlen, path, "span needs start and end "
		    "times"));
	if (strtoull(et->s, NULL, 10) < strtoull(st->s, NULL, 10))
		return (verr(err, errlen, path, "span ends before it "
		    "starts"));
	if (c != NULL)
		c->spans++;
	return (check_attr_holder(v, path, c, err, errlen));
}

int
otlp_validate_request(const struct jv *v, struct otlp_counts *c, char *err,
    size_t errlen)
{

	if (v->type != JV_OBJ || v->n != 1)
		return (verr(err, errlen, "$", "a request has exactly one "
		    "top-level field"));
	if (c != NULL)
		c->requests++;
	if (strcmp(v->keys[0], "resourceLogs") == 0)
		return (validate_msg(v, &LogsReq, "$", c, err, errlen));
	if (strcmp(v->keys[0], "resourceMetrics") == 0)
		return (validate_msg(v, &MetricsReq, "$", c, err, errlen));
	if (strcmp(v->keys[0], "resourceSpans") == 0)
		return (validate_msg(v, &TracesReq, "$", c, err, errlen));
	return (verr(err, errlen, "$", "unknown request type \"%s\"",
	    v->keys[0]));
}

/* ---------------------------------------------------------------- */
/* Golden comparison						 	*/

static int
match_at(const struct jv *g, const struct jv *a, const char *path, char *err,
    size_t errlen)
{
	const struct jv *av;
	char sub[512];
	size_t i;

	if (g->type == JV_STR && strcmp(g->s, "<any>") == 0) {
		if (a->type == JV_STR || a->type == JV_NUM ||
		    a->type == JV_BOOL)
			return (0);
		return (verr(err, errlen, path, "expected a scalar"));
	}
	if (g->type == JV_STR && strcmp(g->s, "<int>") == 0) {
		if (a->type == JV_STR && int_string_ok(a->s, 1))
			return (0);
		return (verr(err, errlen, path, "expected an integer string"));
	}
	if (g->type == JV_STR && (strcmp(g->s, "<hex32>") == 0 ||
	    strcmp(g->s, "<hex16>") == 0)) {
		if (a->type == JV_STR && hex_id_ok(a->s, g->s[4] == '3' ?
		    32 : 16))
			return (0);
		return (verr(err, errlen, path, "expected a %s id", g->s));
	}
	if (g->type != a->type)
		return (verr(err, errlen, path, "type differs"));
	switch (g->type) {
	case JV_NULL:
		return (0);
	case JV_BOOL:
		if (g->b != a->b)
			return (verr(err, errlen, path, "bool differs"));
		return (0);
	case JV_NUM:
		if (strtod(g->s, NULL) != strtod(a->s, NULL))
			return (verr(err, errlen, path, "number %s != %s",
			    a->s, g->s));
		return (0);
	case JV_STR:
		if (g->slen != a->slen || memcmp(g->s, a->s, g->slen) != 0)
			return (verr(err, errlen, path, "\"%s\" != golden "
			    "\"%s\"", a->s, g->s));
		return (0);
	case JV_ARR:
		if (g->n != a->n)
			return (verr(err, errlen, path, "array has %zu items, "
			    "golden %zu", a->n, g->n));
		for (i = 0; i < g->n; i++) {
			snprintf(sub, sizeof(sub), "%s[%zu]", path, i);
			if (match_at(g->items[i], a->items[i], sub, err,
			    errlen) != 0)
				return (-1);
		}
		return (0);
	case JV_OBJ:
		if (g->n != a->n) {
			for (i = 0; i < a->n; i++)
				if (jv_get(g, a->keys[i]) == NULL)
					return (verr(err, errlen, path,
					    "unexpected field \"%s\"",
					    a->keys[i]));
			for (i = 0; i < g->n; i++)
				if (jv_get(a, g->keys[i]) == NULL)
					break;
			return (verr(err, errlen, path, "missing field "
			    "\"%s\"", i < g->n ? g->keys[i] : "?"));
		}
		for (i = 0; i < g->n; i++) {
			snprintf(sub, sizeof(sub), "%s.%s", path, g->keys[i]);
			av = jv_get(a, g->keys[i]);
			if (av == NULL)
				return (verr(err, errlen, path, "missing "
				    "field \"%s\"", g->keys[i]));
			if (match_at(g->items[i], av, sub, err, errlen) != 0)
				return (-1);
		}
		return (0);
	}
	return (0);
}

int
jv_match(const struct jv *golden, const struct jv *actual, char *err,
    size_t errlen)
{

	return (match_at(golden, actual, "$", err, errlen));
}
