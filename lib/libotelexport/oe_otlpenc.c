/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * OTLP protobuf-JSON encoding.  Follows the proto3 JSON mapping the
 * OTLP/HTTP JSON encoding and the Collector's file exporter use:
 * lowerCamelCase field names, 64-bit integers as decimal strings,
 * enums as integers, trace and span ids as lowercase hex.  Events
 * become LogRecords, aggregation snapshots Metrics, spans Spans.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "otelexport.h"
#include "oe_otlpenc.h"

static uint64_t
ts_unix_nano(const struct timespec *ts)
{

	if (ts->tv_sec < 0)
		return (0);
	return ((uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec);
}

static void
append_kv_string(struct oe_buf *b, const char *key, const char *value,
    int *first)
{

	if (!*first)
		oe_buf_appendstr(b, ",");
	*first = 0;
	oe_buf_appendstr(b, "{\"key\":\"");
	oe_buf_appendjson(b, key);
	oe_buf_appendstr(b, "\",\"value\":{\"stringValue\":\"");
	oe_buf_appendjson(b, value != NULL ? value : "");
	oe_buf_appendstr(b, "\"}}");
}

void
oe_enc_kv(struct oe_buf *b, const struct oe_kv *kv, int *first)
{

	if (!*first)
		oe_buf_appendstr(b, ",");
	*first = 0;
	oe_buf_appendstr(b, "{\"key\":\"");
	oe_buf_appendjson(b, kv->key);
	switch (kv->type) {
	case OE_VAL_INT:
		oe_buf_appendf(b, "\",\"value\":{\"intValue\":\"%jd\"}}",
		    (intmax_t)kv->i);
		break;
	case OE_VAL_BOOL:
		oe_buf_appendf(b, "\",\"value\":{\"boolValue\":%s}}",
		    kv->i != 0 ? "true" : "false");
		break;
	case OE_VAL_DOUBLE:
		/* JSON has no NaN or infinities; proto3 JSON spells them. */
		if (kv->d != kv->d)
			oe_buf_appendstr(b,
			    "\",\"value\":{\"doubleValue\":\"NaN\"}}");
		else if (kv->d > 1.7976931348623157e308 ||
		    kv->d < -1.7976931348623157e308)
			oe_buf_appendf(b, "\",\"value\":{\"doubleValue\":"
			    "\"%sInfinity\"}}", kv->d < 0 ? "-" : "");
		else
			oe_buf_appendf(b, "\",\"value\":{\"doubleValue\":"
			    "%.17g}}", kv->d);
		break;
	case OE_VAL_STRING:
		oe_buf_appendstr(b, "\",\"value\":{\"stringValue\":\"");
		oe_buf_appendjson(b, kv->s != NULL ? kv->s : "");
		oe_buf_appendstr(b, "\"}}");
		break;
	}
}

static char *
build_resource_json(const struct oe_resource *r)
{
	struct oe_buf b;
	size_t i;
	int first = 1;

	oe_buf_init(&b);
	append_kv_string(&b, "service.name", r->service_name, &first);
	append_kv_string(&b, "service.version", r->service_version, &first);
	append_kv_string(&b, "host.name", r->host_name, &first);
	append_kv_string(&b, "host.arch", r->host_arch, &first);
	append_kv_string(&b, "os.type", r->os_name, &first);
	append_kv_string(&b, "os.version", r->os_version, &first);
	append_kv_string(&b, "telemetry.sdk.name", "observablebsd", &first);
	append_kv_string(&b, "telemetry.sdk.language", "c", &first);
	append_kv_string(&b, "telemetry.sdk.version", r->service_version,
	    &first);
	if (r->service_instance_id != NULL)
		append_kv_string(&b, "service.instance.id",
		    r->service_instance_id, &first);
	for (i = 0; i < r->ncustom; i++)
		append_kv_string(&b, r->custom[i].name, r->custom[i].value,
		    &first);
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	return (b.data);
}

int
oe_enc_init(struct oe_otlpenc *enc, const struct oe_resource *r)
{

	enc->scope = strdup(r->service_name);
	enc->version = strdup(r->service_version);
	enc->resource_json = build_resource_json(r);
	if (enc->scope == NULL || enc->version == NULL ||
	    enc->resource_json == NULL) {
		oe_enc_fini(enc);
		return (-1);
	}
	return (0);
}

void
oe_enc_fini(struct oe_otlpenc *enc)
{

	free(enc->scope);
	free(enc->version);
	free(enc->resource_json);
	enc->scope = enc->version = enc->resource_json = NULL;
}

const char *
oe_enc_path(enum oe_signal sig)
{

	switch (sig) {
	case OE_SIGNAL_LOGS:
		return ("v1/logs");
	case OE_SIGNAL_METRICS:
		return ("v1/metrics");
	case OE_SIGNAL_TRACES:
		break;
	}
	return ("v1/traces");
}

int
oe_enc_classify(const char *line)
{

	if (strncmp(line, "{\"resourceLogs\":", 16) == 0)
		return (OE_SIGNAL_LOGS);
	if (strncmp(line, "{\"resourceMetrics\":", 19) == 0)
		return (OE_SIGNAL_METRICS);
	if (strncmp(line, "{\"resourceSpans\":", 17) == 0)
		return (OE_SIGNAL_TRACES);
	return (-1);
}

/* ---------------------------------------------------------------- */
/* Requests								*/

char *
oe_enc_request(const struct oe_otlpenc *enc, enum oe_signal sig,
    char **frags, size_t nfrags, uint64_t drops, size_t *lenp)
{
	static const char *const outer[] = {
		"resourceLogs", "resourceMetrics", "resourceSpans" };
	static const char *const middle[] = {
		"scopeLogs", "scopeMetrics", "scopeSpans" };
	static const char *const inner[] = {
		"logRecords", "metrics", "spans" };
	struct oe_buf b;
	size_t i, reclen;

	oe_buf_init(&b);
	oe_buf_appendf(&b, "{\"%s\":[{\"resource\":{\"attributes\":[",
	    outer[sig]);
	oe_buf_appendstr(&b, enc->resource_json);
	oe_buf_appendf(&b, "]},\"%s\":[{\"scope\":{\"name\":\"", middle[sig]);
	oe_buf_appendjson(&b, enc->scope);
	oe_buf_appendstr(&b, "\",\"version\":\"");
	oe_buf_appendjson(&b, enc->version);
	oe_buf_appendf(&b, "\"},\"%s\":[", inner[sig]);
	for (i = 0; i < nfrags; i++) {
		if (i > 0)
			oe_buf_appendstr(&b, ",");
		if (i == 0 && drops > 0 && sig == OE_SIGNAL_LOGS) {
			/*
			 * Splice a drop-counter attribute into the first
			 * record.  Every log record fragment ends with
			 * "]}" closing its attribute array.
			 */
			reclen = strlen(frags[i]);
			oe_buf_append(&b, frags[i], reclen - 2);
			oe_buf_appendstr(&b, ",{\"key\":\"");
			oe_buf_appendjson(&b, enc->scope);
			oe_buf_appendf(&b,
			    ".drops\",\"value\":{\"intValue\":\"%ju\"}}]}",
			    (uintmax_t)drops);
		} else
			oe_buf_appendstr(&b, frags[i]);
	}
	oe_buf_appendstr(&b, "]}]}]}");
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	*lenp = b.len;
	return (b.data);
}

/* ---------------------------------------------------------------- */
/* Log records							 	*/

char *
oe_enc_log_record(const struct oe_otlpenc *enc, const struct oe_event *ev)
{
	struct oe_buf b;
	struct timespec now;
	uint64_t tnano, onano;

	tnano = ts_unix_nano(&ev->ts);
	if (ev->observed.tv_sec != 0 || ev->observed.tv_nsec != 0)
		onano = ts_unix_nano(&ev->observed);
	else {
		clock_gettime(CLOCK_REALTIME, &now);
		onano = ts_unix_nano(&now);
	}
	oe_buf_init(&b);
	oe_buf_appendf(&b, "{\"timeUnixNano\":\"%ju\","
	    "\"observedTimeUnixNano\":\"%ju\",\"severityNumber\":9,"
	    "\"severityText\":\"INFO\",\"body\":{\"stringValue\":\"",
	    (uintmax_t)tnano, (uintmax_t)onano);
	oe_buf_appendjson(&b, ev->body);
	oe_buf_appendstr(&b, "\"},\"attributes\":[{\"key\":\"");
	oe_buf_appendjson(&b, enc->scope);
	oe_buf_appendstr(&b, ".profile\",\"value\":{\"stringValue\":\"");
	oe_buf_appendjson(&b, ev->profile);
	oe_buf_appendstr(&b, "\"}},{\"key\":\"");
	oe_buf_appendjson(&b, enc->scope);
	oe_buf_appendstr(&b, ".probe\",\"value\":{\"stringValue\":\"");
	oe_buf_appendjson(&b, ev->probe != NULL ? ev->probe : "");
	oe_buf_appendf(&b, "\"}},{\"key\":\"process.pid\",\"value\":"
	    "{\"intValue\":\"%d\"}},{\"key\":\"process.executable.name\","
	    "\"value\":{\"stringValue\":\"", (int)ev->pid);
	oe_buf_appendjson(&b, ev->execname != NULL ? ev->execname : "");
	oe_buf_appendstr(&b, "\"}}]}");
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	return (b.data);
}

/* ---------------------------------------------------------------- */
/* Spans								*/

char *
oe_enc_span(const struct oe_otlpenc *enc, const struct oe_span *sp)
{
	struct oe_buf b;
	struct oe_kv kv;
	char tid[2 * OE_TRACE_ID_LEN + 1], sid[2 * OE_SPAN_ID_LEN + 1],
	    pid[2 * OE_SPAN_ID_LEN + 1], key[256];
	size_t i;
	int first = 1;

	oe_id_hex(sp->trace_id, OE_TRACE_ID_LEN, tid);
	oe_id_hex(sp->span_id, OE_SPAN_ID_LEN, sid);
	oe_buf_init(&b);
	oe_buf_appendf(&b, "{\"traceId\":\"%s\",\"spanId\":\"%s\",", tid,
	    sid);
	if (!oe_id_is_zero(sp->parent_span_id, OE_SPAN_ID_LEN)) {
		oe_id_hex(sp->parent_span_id, OE_SPAN_ID_LEN, pid);
		oe_buf_appendf(&b, "\"parentSpanId\":\"%s\",", pid);
	}
	oe_buf_appendstr(&b, "\"name\":\"");
	oe_buf_appendjson(&b, sp->name);
	oe_buf_appendf(&b, "\",\"kind\":%d,\"startTimeUnixNano\":\"%ju\","
	    "\"endTimeUnixNano\":\"%ju\",\"attributes\":[",
	    (int)sp->kind, (uintmax_t)ts_unix_nano(&sp->start),
	    (uintmax_t)ts_unix_nano(&sp->end));
	snprintf(key, sizeof(key), "%s.profile", enc->scope);
	kv.key = key;
	kv.type = OE_VAL_STRING;
	kv.s = sp->profile;
	oe_enc_kv(&b, &kv, &first);
	if (sp->probe != NULL && sp->probe[0] != '\0') {
		snprintf(key, sizeof(key), "%s.probe", enc->scope);
		kv.s = sp->probe;
		oe_enc_kv(&b, &kv, &first);
	}
	if (sp->pid != 0) {
		kv.key = "process.pid";
		kv.type = OE_VAL_INT;
		kv.i = sp->pid;
		oe_enc_kv(&b, &kv, &first);
	}
	if (sp->execname != NULL && sp->execname[0] != '\0') {
		kv.key = "process.executable.name";
		kv.type = OE_VAL_STRING;
		kv.s = sp->execname;
		oe_enc_kv(&b, &kv, &first);
	}
	for (i = 0; i < sp->nattrs; i++)
		oe_enc_kv(&b, &sp->attrs[i], &first);
	oe_buf_appendf(&b, "],\"status\":{\"code\":%d", (int)sp->status);
	if (sp->status_message != NULL) {
		oe_buf_appendstr(&b, ",\"message\":\"");
		oe_buf_appendjson(&b, sp->status_message);
		oe_buf_appendstr(&b, "\"");
	}
	oe_buf_appendstr(&b, "}}");
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	return (b.data);
}

/* ---------------------------------------------------------------- */
/* Metrics								*/

static void
build_dimension_attrs(struct oe_buf *b, const struct oe_datapoint *dp)
{
	size_t i;
	int first = 1;

	for (i = 0; i < dp->nattrs; i++)
		append_kv_string(b, dp->attrs[i].name, dp->attrs[i].value,
		    &first);
}

static int
bucket_cmp(const void *a, const void *b)
{
	const struct oe_bucket *ba = a, *bb = b;

	if (ba->upper < bb->upper)
		return (-1);
	return (ba->upper > bb->upper);
}

/*
 * Build one snapshot's metric JSON fragment.  count/sum become a
 * monotonic Sum, min/max/avg/stddev a Gauge, quantize variants a
 * Histogram (sum omitted — power-of-2 bucket bounds can't recover
 * the true sum of observations).
 */
char *
oe_enc_metric(const struct oe_otlpenc *enc, const struct oe_snapshot *sn)
{
	static const char *const kindnames[] = {
		"count", "sum", "min", "max", "avg", "stddev",
		"quantize", "lquantize", "llquantize"
	};
	struct oe_buf b;
	struct oe_bucket *sorted;
	const struct oe_datapoint *dp;
	char startbuf[64];
	uint64_t tnano;
	int64_t total;
	size_t i, j;
	int firstdp;

	oe_buf_init(&b);
	tnano = ts_unix_nano(&sn->ts);
	startbuf[0] = '\0';
	if (sn->start.tv_sec > 0)
		snprintf(startbuf, sizeof(startbuf),
		    "\"startTimeUnixNano\":\"%ju\",",
		    (uintmax_t)ts_unix_nano(&sn->start));

	oe_buf_appendstr(&b, "{\"name\":\"");
	oe_buf_appendjson(&b, enc->scope);
	oe_buf_appendstr(&b, ".");
	oe_buf_appendjson(&b, sn->profile);
	oe_buf_appendstr(&b, ".");
	if (sn->name != NULL && sn->name[0] != '\0')
		oe_buf_appendjson(&b, sn->name);
	else
		oe_buf_appendstr(&b, kindnames[sn->kind]);
	oe_buf_appendstr(&b, "\",");

	switch (sn->kind) {
	case OE_AGG_COUNT:
	case OE_AGG_SUM:
	case OE_AGG_MIN:
	case OE_AGG_MAX:
	case OE_AGG_AVG:
	case OE_AGG_STDDEV:
		oe_buf_appendstr(&b, sn->kind == OE_AGG_COUNT ||
		    sn->kind == OE_AGG_SUM ?
		    "\"sum\":{\"dataPoints\":[" :
		    "\"gauge\":{\"dataPoints\":[");
		firstdp = 1;
		for (i = 0; i < sn->npoints; i++) {
			dp = &sn->points[i];
			if (dp->is_histogram)
				continue;
			if (!firstdp)
				oe_buf_appendstr(&b, ",");
			firstdp = 0;
			/* Gauges carry no start time. */
			oe_buf_appendf(&b,
			    "{%s\"timeUnixNano\":\"%ju\",\"asInt\":\"%jd\","
			    "\"attributes\":[", sn->kind == OE_AGG_COUNT ||
			    sn->kind == OE_AGG_SUM ? startbuf : "",
			    (uintmax_t)tnano, (intmax_t)dp->scalar);
			build_dimension_attrs(&b, dp);
			oe_buf_appendstr(&b, "]}");
		}
		if (sn->kind == OE_AGG_COUNT || sn->kind == OE_AGG_SUM)
			oe_buf_appendstr(&b, "],\"aggregationTemporality\":2,"
			    "\"isMonotonic\":true}}");
		else
			oe_buf_appendstr(&b, "]}}");
		break;

	case OE_AGG_QUANTIZE:
	case OE_AGG_LQUANTIZE:
	case OE_AGG_LLQUANTIZE:
		oe_buf_appendstr(&b, "\"histogram\":{\"dataPoints\":[");
		firstdp = 1;
		for (i = 0; i < sn->npoints; i++) {
			dp = &sn->points[i];
			/*
			 * A histogram with zero buckets would emit
			 * bucketCounts=[] with explicitBounds=[],
			 * violating len(counts) == len(bounds)+1.
			 */
			if (!dp->is_histogram || dp->nbuckets == 0)
				continue;
			sorted = malloc(dp->nbuckets * sizeof(*sorted));
			if (sorted == NULL) {
				b.error = 1;
				break;
			}
			memcpy(sorted, dp->buckets,
			    dp->nbuckets * sizeof(*sorted));
			qsort(sorted, dp->nbuckets, sizeof(*sorted),
			    bucket_cmp);
			total = 0;
			for (j = 0; j < dp->nbuckets; j++)
				total += sorted[j].count;
			if (!firstdp)
				oe_buf_appendstr(&b, ",");
			firstdp = 0;
			oe_buf_appendf(&b,
			    "{%s\"timeUnixNano\":\"%ju\",\"count\":\"%jd\","
			    "\"explicitBounds\":[", startbuf, (uintmax_t)tnano,
			    (intmax_t)total);
			for (j = 0; j + 1 < dp->nbuckets; j++)
				oe_buf_appendf(&b, "%s%jd", j > 0 ? "," : "",
				    (intmax_t)sorted[j].upper);
			oe_buf_appendstr(&b, "],\"bucketCounts\":[");
			for (j = 0; j < dp->nbuckets; j++)
				oe_buf_appendf(&b, "%s\"%jd\"",
				    j > 0 ? "," : "",
				    (intmax_t)sorted[j].count);
			oe_buf_appendstr(&b, "],\"attributes\":[");
			build_dimension_attrs(&b, dp);
			oe_buf_appendstr(&b, "]}");
			free(sorted);
		}
		oe_buf_appendstr(&b, "],\"aggregationTemporality\":2}}");
		break;
	}

	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	return (b.data);
}

/* ---------------------------------------------------------------- */
/* Fragment arrays							*/

int
oe_frags_append(char ***arr, size_t *n, size_t *cap, char *frag)
{
	char **p;
	size_t newcap;

	if (*n == *cap) {
		newcap = *cap == 0 ? 64 : *cap * 2;
		p = realloc(*arr, newcap * sizeof(*p));
		if (p == NULL)
			return (-1);
		*arr = p;
		*cap = newcap;
	}
	(*arr)[(*n)++] = frag;
	return (0);
}

void
oe_frags_free(char **arr, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(arr[i]);
	free(arr);
}
