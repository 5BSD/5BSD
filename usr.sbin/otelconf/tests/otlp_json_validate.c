/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otlp_json_validate - check OTLP/JSON export requests independently
 * of libotelexport (the documents are parsed with libucl's JSON
 * parser, not produced or read by the exporter code).
 *
 * Checks the OTLP/JSON encoding rules for ExportMetricsServiceRequest
 * and ExportLogsServiceRequest: required structure, one data kind per
 * metric, 64-bit integers as decimal strings, histogram bucket and
 * bound counts, strictly increasing bounds, severity ranges and
 * AnyValue shapes.  Unless -q is given, prints one line per resource
 * attribute, data point and log record for tests to match:
 *
 *	resource <key>=<value>
 *	scope <name>
 *	metric <name> <gauge|sum|histogram> monotonic=<0|1>
 *	point <metric> [k=v,...] <value | count=N buckets=a/b/c>
 *	log <severity> [k=v,...] <body>
 */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

static bool quiet;
static const char *curfile;
static char ctx[256];

static void __dead2
fail(const char *fmt, ...) __printflike(1, 2);

static void __dead2
fail(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "otlp_json_validate: %s: %s: ", curfile, ctx);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void
out(const char *fmt, ...) __printflike(1, 2);

static void
out(const char *fmt, ...)
{
	va_list ap;

	if (quiet)
		return;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static const ucl_object_t *
need(const ucl_object_t *o, const char *key, ucl_type_t type)
{
	const ucl_object_t *v;

	v = ucl_object_lookup(o, key);
	if (v == NULL)
		fail("missing \"%s\"", key);
	if (ucl_object_type(v) != type)
		fail("\"%s\" has the wrong JSON type", key);
	return (v);
}

static const ucl_object_t *
maybe(const ucl_object_t *o, const char *key, ucl_type_t type)
{
	const ucl_object_t *v;

	v = ucl_object_lookup(o, key);
	if (v != NULL && ucl_object_type(v) != type)
		fail("\"%s\" has the wrong JSON type", key);
	return (v);
}

/* OTLP/JSON encodes (u)int64 as a decimal string (numbers tolerated). */
static int64_t
int64_field(const ucl_object_t *v, const char *what, bool allow_neg)
{
	const char *s, *p;
	char *end;
	int64_t n;

	if (ucl_object_type(v) == UCL_INT)
		return (ucl_object_toint(v));
	if (ucl_object_type(v) != UCL_STRING)
		fail("%s must be a decimal string", what);
	s = ucl_object_tostring(v);
	p = s;
	if (allow_neg && *p == '-')
		p++;
	if (*p == '\0' || strspn(p, "0123456789") != strlen(p))
		fail("%s \"%s\" is not a decimal integer", what, s);
	errno = 0;
	n = strtoll(s, &end, 10);
	if (errno != 0 && !allow_neg)
		/* uint64 above INT64_MAX: still valid, clamp for checks. */
		return (INT64_MAX);
	return (n);
}

static void
anyvalue(const ucl_object_t *v, char *buf, size_t len)
{
	const ucl_object_t *x;
	int kinds;

	if (ucl_object_type(v) != UCL_OBJECT)
		fail("AnyValue must be an object");
	kinds = 0;
	buf[0] = '\0';
	if ((x = maybe(v, "stringValue", UCL_STRING)) != NULL) {
		snprintf(buf, len, "%s", ucl_object_tostring(x));
		kinds++;
	}
	if ((x = ucl_object_lookup(v, "intValue")) != NULL) {
		snprintf(buf, len, "%" PRId64, int64_field(x, "intValue",
		    true));
		kinds++;
	}
	if ((x = ucl_object_lookup(v, "doubleValue")) != NULL) {
		if (ucl_object_type(x) != UCL_FLOAT &&
		    ucl_object_type(x) != UCL_INT)
			fail("doubleValue must be a number");
		snprintf(buf, len, "%g", ucl_object_todouble(x));
		kinds++;
	}
	if ((x = maybe(v, "boolValue", UCL_BOOLEAN)) != NULL) {
		snprintf(buf, len, "%s", ucl_object_toboolean(x) ? "true" :
		    "false");
		kinds++;
	}
	if (maybe(v, "arrayValue", UCL_OBJECT) != NULL) {
		snprintf(buf, len, "<array>");
		kinds++;
	}
	if (maybe(v, "kvlistValue", UCL_OBJECT) != NULL) {
		snprintf(buf, len, "<kvlist>");
		kinds++;
	}
	if (maybe(v, "bytesValue", UCL_STRING) != NULL) {
		snprintf(buf, len, "<bytes>");
		kinds++;
	}
	if (kinds != 1)
		fail("AnyValue must hold exactly one value, has %d", kinds);
}

/* Validate a KeyValue list; render "k=v,k=v" into buf. */
static void
attributes(const ucl_object_t *list, char *buf, size_t len)
{
	const ucl_object_t *kv, *key;
	ucl_object_iter_t it;
	char val[512];
	size_t used;

	buf[0] = '\0';
	if (list == NULL)
		return;
	if (ucl_object_type(list) != UCL_ARRAY)
		fail("attributes must be an array");
	used = 0;
	it = NULL;
	while ((kv = ucl_object_iterate(list, &it, true)) != NULL) {
		key = need(kv, "key", UCL_STRING);
		if (ucl_object_tostring(key)[0] == '\0')
			fail("attribute with an empty key");
		anyvalue(need(kv, "value", UCL_OBJECT), val, sizeof(val));
		used += snprintf(buf + used, used < len ? len - used : 0,
		    "%s%s=%s", used > 0 ? "," : "", ucl_object_tostring(key),
		    val);
	}
}

static void
check_time(const ucl_object_t *o, const char *key, bool required)
{
	const ucl_object_t *v;

	v = ucl_object_lookup(o, key);
	if (v == NULL) {
		if (required)
			fail("missing \"%s\"", key);
		return;
	}
	(void)int64_field(v, key, false);
}

static void
resource(const ucl_object_t *r)
{
	const ucl_object_t *res, *kv;
	ucl_object_iter_t it;
	char val[512];

	res = need(r, "resource", UCL_OBJECT);
	it = NULL;
	while ((kv = ucl_object_iterate(maybe(res, "attributes", UCL_ARRAY),
	    &it, true)) != NULL) {
		anyvalue(need(kv, "value", UCL_OBJECT), val, sizeof(val));
		out("resource %s=%s\n", ucl_object_tostring(need(kv, "key",
		    UCL_STRING)), val);
	}
}

static void
scope(const ucl_object_t *s)
{
	const ucl_object_t *sc;

	sc = maybe(s, "scope", UCL_OBJECT);
	if (sc != NULL)
		out("scope %s\n", ucl_object_tostring(need(sc, "name",
		    UCL_STRING)));
}

static void
number_points(const char *name, const ucl_object_t *data)
{
	const ucl_object_t *dp, *v;
	ucl_object_iter_t it;
	char attrs[1024];
	int n;

	it = NULL;
	while ((dp = ucl_object_iterate(need(data, "dataPoints", UCL_ARRAY),
	    &it, true)) != NULL) {
		check_time(dp, "timeUnixNano", true);
		check_time(dp, "startTimeUnixNano", false);
		attributes(ucl_object_lookup(dp, "attributes"), attrs,
		    sizeof(attrs));
		n = 0;
		if ((v = ucl_object_lookup(dp, "asInt")) != NULL) {
			out("point %s [%s] %" PRId64 "\n", name, attrs,
			    int64_field(v, "asInt", true));
			n++;
		}
		if ((v = ucl_object_lookup(dp, "asDouble")) != NULL) {
			if (ucl_object_type(v) != UCL_FLOAT &&
			    ucl_object_type(v) != UCL_INT)
				fail("asDouble must be a number");
			out("point %s [%s] %g\n", name, attrs,
			    ucl_object_todouble(v));
			n++;
		}
		if (n != 1)
			fail("data point of %s needs exactly one of asInt and "
			    "asDouble", name);
	}
}

static void
temporality(const ucl_object_t *data)
{
	int64_t t;

	t = ucl_object_toint(need(data, "aggregationTemporality", UCL_INT));
	if (t != 1 && t != 2)
		fail("aggregationTemporality %" PRId64 " is not 1 or 2", t);
}

static void
histogram_points(const char *name, const ucl_object_t *data)
{
	const ucl_object_t *dp, *b, *c;
	ucl_object_iter_t it, bit;
	char attrs[1024], buckets[1024];
	double prev, bound;
	int64_t count, sum;
	size_t nb, nc, used;

	temporality(data);
	it = NULL;
	while ((dp = ucl_object_iterate(need(data, "dataPoints", UCL_ARRAY),
	    &it, true)) != NULL) {
		check_time(dp, "timeUnixNano", true);
		attributes(ucl_object_lookup(dp, "attributes"), attrs,
		    sizeof(attrs));
		count = int64_field(need(dp, "count", UCL_STRING), "count",
		    false);
		nb = 0;
		prev = 0;
		bit = NULL;
		while ((b = ucl_object_iterate(need(dp, "explicitBounds",
		    UCL_ARRAY), &bit, true)) != NULL) {
			if (ucl_object_type(b) != UCL_INT &&
			    ucl_object_type(b) != UCL_FLOAT)
				fail("explicitBounds must be numbers");
			bound = ucl_object_todouble(b);
			if (nb > 0 && bound <= prev)
				fail("explicitBounds of %s not strictly "
				    "increasing", name);
			prev = bound;
			nb++;
		}
		nc = 0;
		sum = 0;
		used = 0;
		buckets[0] = '\0';
		bit = NULL;
		while ((c = ucl_object_iterate(need(dp, "bucketCounts",
		    UCL_ARRAY), &bit, true)) != NULL) {
			int64_t v = int64_field(c, "bucketCounts", false);

			sum += v;
			used += snprintf(buckets + used, used <
			    sizeof(buckets) ? sizeof(buckets) - used : 0,
			    "%s%" PRId64, nc > 0 ? "/" : "", v);
			nc++;
		}
		if (nc != nb + 1)
			fail("%s: %zu bucketCounts for %zu explicitBounds",
			    name, nc, nb);
		if (sum != count)
			fail("%s: bucketCounts sum %" PRId64 " != count %"
			    PRId64, name, sum, count);
		out("point %s [%s] count=%" PRId64 " buckets=%s\n", name,
		    attrs, count, buckets);
	}
}

static void
metrics_doc(const ucl_object_t *root)
{
	const ucl_object_t *rm, *sm, *m, *data, *mono;
	ucl_object_iter_t i1, i2, i3;
	const char *name;
	int kinds, nmetrics;

	nmetrics = 0;
	i1 = NULL;
	while ((rm = ucl_object_iterate(need(root, "resourceMetrics",
	    UCL_ARRAY), &i1, true)) != NULL) {
		snprintf(ctx, sizeof(ctx), "resourceMetrics");
		resource(rm);
		i2 = NULL;
		while ((sm = ucl_object_iterate(need(rm, "scopeMetrics",
		    UCL_ARRAY), &i2, true)) != NULL) {
			scope(sm);
			i3 = NULL;
			while ((m = ucl_object_iterate(need(sm, "metrics",
			    UCL_ARRAY), &i3, true)) != NULL) {
				name = ucl_object_tostring(need(m, "name",
				    UCL_STRING));
				snprintf(ctx, sizeof(ctx), "metric %s", name);
				if (name[0] == '\0')
					fail("empty metric name");
				kinds = 0;
				if ((data = maybe(m, "gauge",
				    UCL_OBJECT)) != NULL) {
					kinds++;
					out("metric %s gauge monotonic=0\n",
					    name);
					number_points(name, data);
				}
				if ((data = maybe(m, "sum",
				    UCL_OBJECT)) != NULL) {
					kinds++;
					temporality(data);
					mono = maybe(data, "isMonotonic",
					    UCL_BOOLEAN);
					out("metric %s sum monotonic=%d\n",
					    name, mono != NULL &&
					    ucl_object_toboolean(mono));
					number_points(name, data);
				}
				if ((data = maybe(m, "histogram",
				    UCL_OBJECT)) != NULL) {
					kinds++;
					out("metric %s histogram "
					    "monotonic=0\n", name);
					histogram_points(name, data);
				}
				if (maybe(m, "exponentialHistogram",
				    UCL_OBJECT) != NULL ||
				    maybe(m, "summary", UCL_OBJECT) != NULL)
					kinds++;
				if (kinds != 1)
					fail("metric needs exactly one data "
					    "kind, has %d", kinds);
				nmetrics++;
			}
		}
	}
	if (nmetrics == 0) {
		snprintf(ctx, sizeof(ctx), "resourceMetrics");
		fail("request carries no metrics");
	}
}

static void
logs_doc(const ucl_object_t *root)
{
	const ucl_object_t *rl, *sl, *lr, *sev;
	ucl_object_iter_t i1, i2, i3;
	char attrs[2048], body[2048];
	int64_t s;
	int nlogs;

	nlogs = 0;
	i1 = NULL;
	while ((rl = ucl_object_iterate(need(root, "resourceLogs", UCL_ARRAY),
	    &i1, true)) != NULL) {
		snprintf(ctx, sizeof(ctx), "resourceLogs");
		resource(rl);
		i2 = NULL;
		while ((sl = ucl_object_iterate(need(rl, "scopeLogs",
		    UCL_ARRAY), &i2, true)) != NULL) {
			scope(sl);
			i3 = NULL;
			while ((lr = ucl_object_iterate(need(sl, "logRecords",
			    UCL_ARRAY), &i3, true)) != NULL) {
				snprintf(ctx, sizeof(ctx), "logRecord %d",
				    nlogs);
				check_time(lr, "timeUnixNano", false);
				check_time(lr, "observedTimeUnixNano", false);
				s = 0;
				sev = ucl_object_lookup(lr, "severityNumber");
				if (sev != NULL) {
					if (ucl_object_type(sev) != UCL_INT)
						fail("severityNumber must be "
						    "an integer");
					s = ucl_object_toint(sev);
					if (s < 0 || s > 24)
						fail("severityNumber %" PRId64
						    " outside 0..24", s);
				}
				(void)maybe(lr, "severityText", UCL_STRING);
				body[0] = '\0';
				if (ucl_object_lookup(lr, "body") != NULL)
					anyvalue(ucl_object_lookup(lr, "body"),
					    body, sizeof(body));
				attributes(ucl_object_lookup(lr,
				    "attributes"), attrs, sizeof(attrs));
				out("log %" PRId64 " [%s] %s\n", s, attrs,
				    body);
				nlogs++;
			}
		}
	}
	if (nlogs == 0) {
		snprintf(ctx, sizeof(ctx), "resourceLogs");
		fail("request carries no log records");
	}
}

static void
validate(const char *path)
{
	struct ucl_parser *p;
	ucl_object_t *root;

	curfile = path;
	snprintf(ctx, sizeof(ctx), "document");
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	if (p == NULL)
		err(1, "ucl_parser_new");
	if (!ucl_parser_add_file(p, path))
		fail("not valid JSON: %s", ucl_parser_get_error(p));
	root = ucl_parser_get_object(p);
	if (ucl_object_type(root) != UCL_OBJECT)
		fail("top level must be an object");
	if (ucl_object_lookup(root, "resourceMetrics") != NULL &&
	    ucl_object_lookup(root, "resourceLogs") != NULL)
		fail("mixes metrics and logs");
	if (ucl_object_lookup(root, "resourceMetrics") != NULL)
		metrics_doc(root);
	else if (ucl_object_lookup(root, "resourceLogs") != NULL)
		logs_doc(root);
	else
		fail("neither resourceMetrics nor resourceLogs");
	ucl_object_unref(root);
	ucl_parser_free(p);
}

int
main(int argc, char **argv)
{
	int ch, i;

	while ((ch = getopt(argc, argv, "q")) != -1) {
		switch (ch) {
		case 'q':
			quiet = true;
			break;
		default:
			fprintf(stderr, "usage: otlp_json_validate [-q] "
			    "file ...\n");
			return (2);
		}
	}
	if (optind == argc) {
		fprintf(stderr, "usage: otlp_json_validate [-q] file ...\n");
		return (2);
	}
	for (i = optind; i < argc; i++)
		validate(argv[i]);
	return (0);
}
