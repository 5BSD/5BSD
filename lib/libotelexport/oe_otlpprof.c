/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * OTLP profiles (experimental): one profile as an
 * ExportProfilesServiceRequest of opentelemetry-proto 1.10
 * (opentelemetry.proto.collector.profiles.v1development), in the OTLP
 * JSON encoding the rest of the library writes (lowerCamelCase, 64-bit
 * integers as strings, hex trace and span ids).  The protobuf transports
 * transcode it to the binary request (oe_otlppb.c); the OTLP JSON Lines
 * file exporter writes it as one line.  The JSON mapping of the profiles
 * signal is at Development maturity, as is the protobuf one.
 *
 * The dictionary is built per request (oe_profdict.c).  The scope names
 * the proto package and release so consumers can tell which draft of the
 * signal they receive.
 */

#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "otelexport.h"
#include "oe_otlpenc.h"
#include "oe_profdict.h"

#define	PROFILES_PACKAGE	"opentelemetry.proto.profiles.v1development"
#define	PROFILES_PROTO_VERSION	"1.10.0"

static uint64_t
ts_nano(const struct timespec *ts)
{

	if (ts->tv_sec < 0)
		return (0);
	return ((uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec);
}

static void
enc_double(struct oe_buf *b, double d)
{

	if (d != d)
		oe_buf_appendstr(b, "\"NaN\"");
	else if (d > 1.7976931348623157e308 || d < -1.7976931348623157e308)
		oe_buf_appendf(b, "\"%sInfinity\"", d < 0 ? "-" : "");
	else
		oe_buf_appendf(b, "%.17g", d);
}

static void
enc_indices(struct oe_buf *b, const char *key, const int32_t *idx, size_t n)
{
	size_t i;

	if (n == 0)
		return;
	oe_buf_appendf(b, ",\"%s\":[", key);
	for (i = 0; i < n; i++)
		oe_buf_appendf(b, "%s%d", i > 0 ? "," : "", (int)idx[i]);
	oe_buf_appendstr(b, "]");
}

static void
enc_dictionary(struct oe_buf *b, const struct oe_profdict *d)
{
	char tid[2 * OE_TRACE_ID_LEN + 1], sid[2 * OE_SPAN_ID_LEN + 1];
	size_t i;

	/*
	 * Entry 0 of every table is the zero value: an empty object (a
	 * leading comma keeps the JSON valid for the optional fields).
	 */
	oe_buf_appendstr(b, "\"dictionary\":{\"mappingTable\":[{}");
	for (i = 1; i < d->nmappings; i++)
		oe_buf_appendf(b, ",{\"filenameStrindex\":%d}",
		    (int)d->mappings[i].filename);
	oe_buf_appendstr(b, "],\"locationTable\":[{}");
	for (i = 1; i < d->nlocations; i++) {
		const struct oe_pd_location *l = &d->locations[i];

		oe_buf_appendf(b, ",{\"mappingIndex\":%d,\"address\":\"%ju\"",
		    (int)l->mapping, (uintmax_t)l->address);
		if (l->function != 0)
			oe_buf_appendf(b, ",\"lines\":[{\"functionIndex\":%d}]",
			    (int)l->function);
		oe_buf_appendstr(b, "}");
	}
	oe_buf_appendstr(b, "],\"functionTable\":[{}");
	for (i = 1; i < d->nfunctions; i++)
		oe_buf_appendf(b, ",{\"nameStrindex\":%d,"
		    "\"systemNameStrindex\":%d}", (int)d->functions[i].name,
		    (int)d->functions[i].system_name);
	oe_buf_appendstr(b, "],\"linkTable\":[{}");
	for (i = 1; i < d->nlinks; i++) {
		oe_id_hex(d->links[i].trace_id, OE_TRACE_ID_LEN, tid);
		oe_id_hex(d->links[i].span_id, OE_SPAN_ID_LEN, sid);
		oe_buf_appendf(b, ",{\"traceId\":\"%s\",\"spanId\":\"%s\"}",
		    tid, sid);
	}
	oe_buf_appendstr(b, "],\"stringTable\":[");
	for (i = 0; i < d->nstrings; i++) {
		oe_buf_appendstr(b, i > 0 ? ",\"" : "\"");
		oe_buf_appendjson(b, d->strings[i]);
		oe_buf_appendstr(b, "\"");
	}
	oe_buf_appendstr(b, "],\"attributeTable\":[{}");
	for (i = 1; i < d->nattrs; i++) {
		const struct oe_pd_attr *a = &d->attrs[i];

		oe_buf_appendf(b, ",{\"keyStrindex\":%d,\"value\":{",
		    (int)a->key);
		switch (a->type) {
		case OE_VAL_STRING:
			oe_buf_appendstr(b, "\"stringValue\":\"");
			oe_buf_appendjson(b, a->s);
			oe_buf_appendstr(b, "\"");
			break;
		case OE_VAL_INT:
			oe_buf_appendf(b, "\"intValue\":\"%jd\"",
			    (intmax_t)a->i);
			break;
		case OE_VAL_BOOL:
			oe_buf_appendf(b, "\"boolValue\":%s",
			    a->i != 0 ? "true" : "false");
			break;
		case OE_VAL_DOUBLE:
			oe_buf_appendstr(b, "\"doubleValue\":");
			enc_double(b, a->d);
			break;
		}
		oe_buf_appendstr(b, "}}");
	}
	oe_buf_appendstr(b, "],\"stackTable\":[{}");
	for (i = 1; i < d->nstacks; i++) {
		oe_buf_appendstr(b, ",{\"locationIndices\":[");
		for (size_t j = 0; j < d->stacks[i].n; j++)
			oe_buf_appendf(b, "%s%d", j > 0 ? "," : "",
			    (int)d->stacks[i].locations[j]);
		oe_buf_appendstr(b, "]}");
	}
	oe_buf_appendstr(b, "]}");
}

static void
enc_sample(struct oe_buf *b, const struct oe_pd_sample *s, int first)
{
	size_t i;

	oe_buf_appendf(b, "%s{\"stackIndex\":%d", first ? "" : ",",
	    (int)s->stack);
	enc_indices(b, "attributeIndices", s->attrs, s->nattrs);
	if (s->link != 0)
		oe_buf_appendf(b, ",\"linkIndex\":%d", (int)s->link);
	if (s->nvalues > 0) {
		oe_buf_appendstr(b, ",\"values\":[");
		for (i = 0; i < s->nvalues; i++)
			oe_buf_appendf(b, "%s\"%jd\"", i > 0 ? "," : "",
			    (intmax_t)s->values[i]);
		oe_buf_appendstr(b, "]");
	}
	if (s->ntimestamps > 0) {
		oe_buf_appendstr(b, ",\"timestampsUnixNano\":[");
		for (i = 0; i < s->ntimestamps; i++)
			oe_buf_appendf(b, "%s\"%ju\"", i > 0 ? "," : "",
			    (uintmax_t)s->timestamps[i]);
		oe_buf_appendstr(b, "]");
	}
	oe_buf_appendstr(b, "}");
}

/* A string index for a ValueType member, or -1. */
static int32_t
vt_string(struct oe_profdict *d, const char *s)
{

	return (oe_profdict_string(d, s != NULL ? s : ""));
}

char *
oe_enc_profile(const struct oe_otlpenc *enc, const struct oe_profile *pr,
    size_t *lenp)
{
	struct oe_profdict d;
	struct oe_buf b;
	struct oe_kv kv;
	int32_t st, su, pt = 0, pu = 0, *pattrs, idx;
	uint64_t start, end;
	char key[256];
	size_t i, npattrs;

	if (oe_profdict_init(&d, 0) != 0)
		return (NULL);
	pattrs = calloc(pr->nattrs + 1, sizeof(*pattrs));
	if (pattrs == NULL) {
		oe_profdict_fini(&d);
		return (NULL);
	}
	st = vt_string(&d, pr->sample_type);
	su = vt_string(&d, pr->sample_unit);
	if (pr->period_type != NULL) {
		pt = vt_string(&d, pr->period_type);
		pu = vt_string(&d, pr->period_unit);
	}
	/* "<scope>.profile" names the profile, as for log records. */
	snprintf(key, sizeof(key), "%s.profile", enc->scope);
	kv.key = key;
	kv.type = OE_VAL_STRING;
	kv.s = pr->profile != NULL ? pr->profile : "";
	npattrs = 0;
	for (i = 0; i <= pr->nattrs; i++) {
		if (i > 0 && strcmp(pr->attrs[i - 1].key, key) == 0)
			continue;
		/* Only a full table refuses: the attribute is left out. */
		if ((idx = oe_profdict_attr(&d, i == 0 ? &kv :
		    &pr->attrs[i - 1])) >= 0)
			pattrs[npattrs++] = idx;
	}
	for (i = 0; i < pr->nsamples; i++)
		(void)oe_profdict_sample(&d, &pr->samples[i]);
	/*
	 * The type strings are interned first, into a nearly empty
	 * dictionary: only a lack of memory (d.error) refuses them.
	 */
	if (d.error) {
		free(pattrs);
		oe_profdict_fini(&d);
		return (NULL);
	}
	if (d.dropped > 0)
		fprintf(stderr, "otlp: profile %s: %ju samples dropped (the "
		    "profile dictionary is full)\n", kv.s,
		    (uintmax_t)d.dropped);

	start = ts_nano(&pr->start);
	end = ts_nano(&pr->end);
	oe_buf_init(&b);
	oe_buf_appendstr(&b, "{\"resourceProfiles\":[{\"resource\":"
	    "{\"attributes\":[");
	oe_buf_appendstr(&b, enc->resource_json);
	oe_buf_appendstr(&b, "]},\"scopeProfiles\":[{\"scope\":{\"name\":\"");
	oe_buf_appendjson(&b, enc->scope);
	oe_buf_appendstr(&b, "\",\"version\":\"");
	oe_buf_appendjson(&b, enc->version);
	oe_buf_appendstr(&b, "\",\"attributes\":[{\"key\":"
	    "\"otlp.profiles.package\",\"value\":{\"stringValue\":\""
	    PROFILES_PACKAGE "\"}},{\"key\":\"otlp.proto.version\","
	    "\"value\":{\"stringValue\":\"" PROFILES_PROTO_VERSION "\"}}]},"
	    "\"profiles\":[{");
	oe_buf_appendf(&b, "\"sampleType\":{\"typeStrindex\":%d,"
	    "\"unitStrindex\":%d},\"samples\":[", (int)st, (int)su);
	for (i = 0; i < d.nsamples; i++)
		enc_sample(&b, &d.samples[i], i == 0);
	oe_buf_appendf(&b, "],\"timeUnixNano\":\"%ju\",\"durationNano\":"
	    "\"%ju\"", (uintmax_t)start, (uintmax_t)(end > start ?
	    end - start : 0));
	if (pr->period_type != NULL)
		oe_buf_appendf(&b, ",\"periodType\":{\"typeStrindex\":%d,"
		    "\"unitStrindex\":%d},\"period\":\"%jd\"", (int)pt,
		    (int)pu, (intmax_t)pr->period);
	enc_indices(&b, "attributeIndices", pattrs, npattrs);
	oe_buf_appendstr(&b, "}]}]}],");
	enc_dictionary(&b, &d);
	oe_buf_appendstr(&b, "}");
	free(pattrs);
	oe_profdict_fini(&d);
	if (b.error) {
		oe_buf_free(&b);
		return (NULL);
	}
	*lenp = b.len;
	return (b.data);
}
