/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * OTLP protobuf encoding: transcode the OTLP JSON requests of the
 * shared encoder (oe_otlpenc.c) to binary Export*ServiceRequest
 * messages, and decode the binary responses.
 *
 * The transcoder is generic over the opentelemetry-proto definitions:
 * it walks the parsed JSON (libucl) against the upb reflection
 * definitions generated from contrib/opentelemetry-proto at build time
 * (lib/protobuf/protoc-gen.mk) and fills a upb message, which upb then
 * serializes.  It implements the OTLP/HTTP JSON encoding, which is the
 * proto3 JSON mapping except that trace and span ids are hex rather
 * than base64 (OTLP specification, "JSON Protobuf Encoding"): field
 * names in lowerCamelCase or as declared, 64-bit integers as numbers or
 * decimal strings, enums as numbers or names, NaN and infinities as
 * strings, other bytes fields as base64, null for a default value.
 * Unknown fields are an error rather than silently dropped; so is a
 * duplicate key, which the parser turns into an array the field does
 * not accept.
 */

#include <sys/param.h>

#include <errno.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

/*
 * upb's inline accessors cast away const and realign by design; the
 * base warning level (with -Wsystem-headers) would reject its headers.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wcast-align"
#include "upb/mem/arena.h"
#include "upb/message/array.h"
#include "upb/message/message.h"
#include "upb/reflection/def.h"
#include "upb/reflection/message.h"
#include "upb/wire/decode.h"
#include "upb/wire/encode.h"

#include "opentelemetry/proto/collector/logs/v1/logs_service.upbdefs.h"
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.upbdefs.h"
#include "opentelemetry/proto/collector/trace/v1/trace_service.upbdefs.h"
#pragma GCC diagnostic pop

#include "otelexport.h"
#include "oe_otlpenc.h"
#include "oe_otlppb.h"

/* Deepest JSON nesting accepted (AnyValue arrays and lists nest). */
#define	OTLPPB_MAX_DEPTH	64

int
oe_otlp_protocol_parse(const char *s)
{

	if (s == NULL)
		return (-1);
	if (strcmp(s, "grpc") == 0)
		return (OE_PROTO_GRPC);
	if (strcmp(s, "http/protobuf") == 0)
		return (OE_PROTO_HTTP_PROTOBUF);
	if (strcmp(s, "http/json") == 0)
		return (OE_PROTO_HTTP_JSON);
	return (-1);
}

const char *
oe_otlp_protocol_name(enum oe_otlp_protocol p)
{

	static const char *const names[] = {
		[OE_PROTO_HTTP_JSON] = "http/json",
		[OE_PROTO_HTTP_PROTOBUF] = "http/protobuf",
		[OE_PROTO_GRPC] = "grpc",
	};

	return (names[p]);
}

int
oe_otlppb_defs_init(struct oe_otlppb_defs *d)
{
	upb_DefPool *p;

	memset(d, 0, sizeof(*d));
	if ((p = upb_DefPool_New()) == NULL)
		return (-1);
	d->pool = p;
/* The generated loader of a collector service message. */
#define	SVCDEF(svc, msg)						\
	opentelemetry_proto_collector_##svc##_v1_##msg##_getmsgdef(p)
	d->request[OE_SIGNAL_LOGS] = SVCDEF(logs, ExportLogsServiceRequest);
	d->response[OE_SIGNAL_LOGS] = SVCDEF(logs, ExportLogsServiceResponse);
	d->request[OE_SIGNAL_METRICS] =
	    SVCDEF(metrics, ExportMetricsServiceRequest);
	d->response[OE_SIGNAL_METRICS] =
	    SVCDEF(metrics, ExportMetricsServiceResponse);
	d->request[OE_SIGNAL_TRACES] = SVCDEF(trace, ExportTraceServiceRequest);
	d->response[OE_SIGNAL_TRACES] =
	    SVCDEF(trace, ExportTraceServiceResponse);
#undef SVCDEF
	/*
	 * The definitions are compiled in; only allocation can fail, and a
	 * failed load leaves its messages (and its dependents') unfound.
	 */
	if (d->request[OE_SIGNAL_LOGS] == NULL ||
	    d->response[OE_SIGNAL_LOGS] == NULL ||
	    d->request[OE_SIGNAL_METRICS] == NULL ||
	    d->response[OE_SIGNAL_METRICS] == NULL ||
	    d->request[OE_SIGNAL_TRACES] == NULL ||
	    d->response[OE_SIGNAL_TRACES] == NULL) {
		oe_otlppb_defs_fini(d);
		return (-1);
	}
	return (0);
}

void
oe_otlppb_defs_fini(struct oe_otlppb_defs *d)
{

	if (d->pool != NULL)
		upb_DefPool_Free(d->pool);
	memset(d, 0, sizeof(*d));
}

/* ---------------------------------------------------------------- */
/* JSON to upb								*/

struct tc {
	upb_Arena	*arena;
	char		*err;
	size_t		 errlen;
};

static int
tc_error(struct tc *t, const upb_FieldDef *f, const char *why)
{

	if (f != NULL)
		snprintf(t->err, t->errlen, "%s.%s: %s",
		    upb_MessageDef_Name(upb_FieldDef_ContainingType(f)),
		    upb_FieldDef_Name(f), why);
	else
		snprintf(t->err, t->errlen, "%s", why);
	return (-1);
}

/* OTLP JSON spells these bytes fields in hex, every other in base64. */
static int
hex_field(const upb_FieldDef *f)
{
	const char *n = upb_FieldDef_Name(f);

	return (strcmp(n, "trace_id") == 0 || strcmp(n, "span_id") == 0 ||
	    strcmp(n, "parent_span_id") == 0);
}

static int
hexval(int c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

static int
decode_hex(const char *s, size_t len, unsigned char *out, size_t *outlen)
{
	size_t i;
	int hi, lo;

	if (len % 2 != 0)
		return (-1);
	for (i = 0; i < len; i += 2) {
		hi = hexval((unsigned char)s[i]);
		lo = hexval((unsigned char)s[i + 1]);
		if (hi < 0 || lo < 0)
			return (-1);
		out[i / 2] = (unsigned char)(hi << 4 | lo);
	}
	*outlen = len / 2;
	return (0);
}

static int
b64val(int c)
{

	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	if (c >= 'a' && c <= 'z')
		return (c - 'a' + 26);
	if (c >= '0' && c <= '9')
		return (c - '0' + 52);
	if (c == '+' || c == '-')
		return (62);
	if (c == '/' || c == '_')
		return (63);
	return (-1);
}

/* Base64, standard or URL-safe alphabet, padding optional (proto3 JSON). */
int
oe_base64_decode(const char *s, size_t len, unsigned char *out, size_t *outlen)
{
	uint32_t acc;
	size_t i, n;
	int bits, v;

	while (len > 0 && s[len - 1] == '=')
		len--;
	if (len % 4 == 1)
		return (-1);
	acc = 0;
	bits = 0;
	n = 0;
	for (i = 0; i < len; i++) {
		if ((v = b64val((unsigned char)s[i])) < 0)
			return (-1);
		acc = acc << 6 | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[n++] = (unsigned char)(acc >> bits);
		}
	}
	*outlen = n;
	return (0);
}

static int
string_view(struct tc *t, const upb_FieldDef *f, const ucl_object_t *v,
    upb_StringView *sv)
{
	const char *s;
	unsigned char *buf;
	size_t len, n;
	int r;

	if (ucl_object_type(v) != UCL_STRING)
		return (tc_error(t, f, "expected a string"));
	s = ucl_object_tolstring(v, &len);
	if ((buf = upb_Arena_Malloc(t->arena, len + 1)) == NULL)
		return (tc_error(t, NULL, "out of memory"));
	if (upb_FieldDef_CType(f) == kUpb_CType_String) {
		memcpy(buf, s, len);
		n = len;
	} else {
		r = hex_field(f) ? decode_hex(s, len, buf, &n) :
		    oe_base64_decode(s, len, buf, &n);
		if (r != 0)
			return (tc_error(t, f, hex_field(f) ?
			    "invalid hex id" : "invalid base64"));
	}
	sv->data = (const char *)buf;
	sv->size = n;
	return (0);
}

/* An integer value: a JSON number or a decimal string. */
static int
integer(struct tc *t, const upb_FieldDef *f, const ucl_object_t *v,
    int is_unsigned, int64_t *sp, uint64_t *up)
{
	const char *s;
	char *end;
	double d;

	switch (ucl_object_type(v)) {
	case UCL_INT:
		*sp = ucl_object_toint(v);
		if (is_unsigned && *sp < 0)
			return (tc_error(t, f, "negative value"));
		*up = (uint64_t)*sp;
		return (0);
	case UCL_FLOAT:
		/* 1.0 and 1e3 are integers in proto3 JSON. */
		d = ucl_object_todouble(v);
		/* In range first: the conversions below are then defined. */
		if (!(d >= (is_unsigned ? 0.0 : -0x1p63) &&
		    d < (is_unsigned ? 0x1p64 : 0x1p63)))
			return (tc_error(t, f, "not an integer"));
		*up = (uint64_t)(is_unsigned ? d : 0);
		*sp = (int64_t)(is_unsigned ? 0 : d);
		if ((is_unsigned ? (double)*up : (double)*sp) != d)
			return (tc_error(t, f, "not an integer"));
		return (0);
	case UCL_STRING:
		s = ucl_object_tostring(v);
		errno = 0;
		if (is_unsigned) {
			if (*s == '-')
				return (tc_error(t, f, "negative value"));
			*up = strtoull(s, &end, 10);
		} else
			*sp = strtoll(s, &end, 10);
		if (end == s || *end != '\0' || errno != 0)
			return (tc_error(t, f, "not an integer"));
		return (0);
	default:
		return (tc_error(t, f, "expected an integer"));
	}
}

static int
floating(struct tc *t, const upb_FieldDef *f, const ucl_object_t *v,
    double *dp)
{
	const char *s;
	char *end;

	switch (ucl_object_type(v)) {
	case UCL_INT:
		*dp = (double)ucl_object_toint(v);
		return (0);
	case UCL_FLOAT:
		*dp = ucl_object_todouble(v);
		return (0);
	case UCL_STRING:
		s = ucl_object_tostring(v);
		if (strcmp(s, "NaN") == 0)
			*dp = NAN;
		else if (strcmp(s, "Infinity") == 0)
			*dp = INFINITY;
		else if (strcmp(s, "-Infinity") == 0)
			*dp = -INFINITY;
		else {
			errno = 0;
			*dp = strtod(s, &end);
			/* strtod's own "inf" and "nan" are not JSON. */
			if (end == s || *end != '\0' || errno != 0 ||
			    *dp != *dp || *dp > DBL_MAX || *dp < -DBL_MAX)
				return (tc_error(t, f, "not a number"));
		}
		return (0);
	default:
		return (tc_error(t, f, "expected a number"));
	}
}

static int	json_message(struct tc *, upb_Message *, const upb_MessageDef *,
		    const ucl_object_t *, int);

/* One JSON value of a (possibly repeated) field. */
static int
json_value(struct tc *t, const upb_FieldDef *f, const ucl_object_t *v,
    upb_MessageValue *val, int depth)
{
	const upb_MessageDef *sub;
	const upb_EnumValueDef *ev;
	upb_Message *m;
	const char *s;
	size_t len;
	int64_t i64;
	uint64_t u64;

	memset(val, 0, sizeof(*val));
	switch (upb_FieldDef_CType(f)) {
	case kUpb_CType_Bool:
		if (ucl_object_type(v) != UCL_BOOLEAN)
			return (tc_error(t, f, "expected true or false"));
		val->bool_val = ucl_object_toboolean(v);
		return (0);
	case kUpb_CType_Double:
		return (floating(t, f, v, &val->double_val));
	case kUpb_CType_Int32:
		if (integer(t, f, v, 0, &i64, &u64) != 0)
			return (-1);
		if (i64 < INT32_MIN || i64 > INT32_MAX)
			return (tc_error(t, f, "out of range"));
		val->int32_val = (int32_t)i64;
		return (0);
	case kUpb_CType_UInt32:
		if (integer(t, f, v, 1, &i64, &u64) != 0)
			return (-1);
		if (u64 > UINT32_MAX)
			return (tc_error(t, f, "out of range"));
		val->uint32_val = (uint32_t)u64;
		return (0);
	case kUpb_CType_Int64:
		return (integer(t, f, v, 0, &val->int64_val, &u64));
	case kUpb_CType_UInt64:
		return (integer(t, f, v, 1, &i64, &val->uint64_val));
	case kUpb_CType_Enum:
		if (ucl_object_type(v) == UCL_STRING) {
			s = ucl_object_tolstring(v, &len);
			ev = upb_EnumDef_FindValueByNameWithSize(
			    upb_FieldDef_EnumSubDef(f), s, len);
			if (ev == NULL)
				return (tc_error(t, f, "unknown enum name"));
			val->int32_val = upb_EnumValueDef_Number(ev);
			return (0);
		}
		if (integer(t, f, v, 0, &i64, &u64) != 0)
			return (-1);
		if (i64 < INT32_MIN || i64 > INT32_MAX)
			return (tc_error(t, f, "out of range"));
		val->int32_val = (int32_t)i64;
		return (0);
	case kUpb_CType_String:
	case kUpb_CType_Bytes:
		return (string_view(t, f, v, &val->str_val));
	case kUpb_CType_Message:
		if (ucl_object_type(v) != UCL_OBJECT)
			return (tc_error(t, f, "expected an object"));
		sub = upb_FieldDef_MessageSubDef(f);
		m = upb_Message_New(upb_MessageDef_MiniTable(sub), t->arena);
		if (m == NULL)
			return (tc_error(t, NULL, "out of memory"));
		if (json_message(t, m, sub, v, depth + 1) != 0)
			return (-1);
		val->msg_val = m;
		return (0);
	case kUpb_CType_Float:
		/* OTLP has no float fields. */
		break;
	}
	return (tc_error(t, f, "unsupported field type"));
}

static int
json_message(struct tc *t, upb_Message *msg, const upb_MessageDef *md,
    const ucl_object_t *obj, int depth)
{
	const ucl_object_t *cur, *elt;
	const upb_FieldDef *f;
	ucl_object_iter_t it, ait;
	upb_MutableMessageValue mut;
	upb_MessageValue val;
	const char *key;
	size_t keylen;

	if (depth > OTLPPB_MAX_DEPTH)
		return (tc_error(t, NULL, "JSON nested too deeply"));
	it = NULL;
	while ((cur = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_keyl(cur, &keylen);
		f = upb_MessageDef_FindByJsonNameWithSize(md, key, keylen);
		if (f == NULL) {
			snprintf(t->err, t->errlen,
			    "%s: unknown field \"%.*s\"",
			    upb_MessageDef_Name(md), (int)keylen, key);
			return (-1);
		}
		/* null is the default value: leave the field unset. */
		if (ucl_object_type(cur) == UCL_NULL)
			continue;
		/*
		 * OTLP has no map fields; one would be refused below, since
		 * proto3 JSON spells a map as an object, not an array.
		 */
		if (!upb_FieldDef_IsRepeated(f)) {
			if (json_value(t, f, cur, &val, depth) != 0)
				return (-1);
			/* Only extensions allocate here; OTLP has none. */
			(void)upb_Message_SetFieldByDef(msg, f, val, t->arena);
			continue;
		}
		if (ucl_object_type(cur) != UCL_ARRAY)
			return (tc_error(t, f, "expected an array"));
		mut = upb_Message_Mutable(msg, f, t->arena);
		if (mut.array == NULL)
			return (tc_error(t, NULL, "out of memory"));
		ait = NULL;
		while ((elt = ucl_object_iterate(cur, &ait, true)) != NULL) {
			if (json_value(t, f, elt, &val, depth) != 0)
				return (-1);
			if (!upb_Array_Append(mut.array, val, t->arena))
				return (tc_error(t, NULL, "out of memory"));
		}
	}
	return (0);
}

int
oe_otlppb_encode(const struct oe_otlppb_defs *d, enum oe_signal sig,
    const char *json, size_t len, char **outp, size_t *outlenp, char *err,
    size_t errlen)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	upb_Message *msg;
	struct tc t;
	char *buf;
	size_t size;
	int ret;

	ret = -1;
	err[0] = '\0';
	*outp = NULL;
	t.err = err;
	t.errlen = errlen;
	if ((t.arena = upb_Arena_New()) == NULL) {
		snprintf(err, errlen, "out of memory");
		return (-1);
	}
	root = NULL;
	parser = ucl_parser_new(UCL_PARSER_NO_TIME | UCL_PARSER_DISABLE_MACRO |
	    UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (parser == NULL) {
		snprintf(err, errlen, "out of memory");
		goto out;
	}
	if (!ucl_parser_add_chunk_full(parser, (const unsigned char *)json,
	    len, 0, UCL_DUPLICATE_APPEND, UCL_PARSE_UCL)) {
		snprintf(err, errlen, "invalid JSON: %s",
		    ucl_parser_get_error(parser));
		goto out;
	}
	root = ucl_parser_get_object(parser);
	if (ucl_object_type(root) != UCL_OBJECT) {
		snprintf(err, errlen, "request is not a JSON object");
		goto out;
	}
	msg = upb_Message_New(upb_MessageDef_MiniTable(d->request[sig]),
	    t.arena);
	if (msg == NULL) {
		snprintf(err, errlen, "out of memory");
		goto out;
	}
	if (json_message(&t, msg, d->request[sig], root, 0) != 0)
		goto out;
	if (upb_Encode(msg, upb_MessageDef_MiniTable(d->request[sig]), 0,
	    t.arena, &buf, &size) != kUpb_EncodeStatus_Ok) {
		snprintf(err, errlen, "protobuf encoding failed");
		goto out;
	}
	/* An empty request still needs a non-NULL buffer. */
	if ((*outp = malloc(size + 1)) == NULL) {
		snprintf(err, errlen, "out of memory");
		goto out;
	}
	memcpy(*outp, buf, size);
	*outlenp = size;
	ret = 0;
out:
	if (root != NULL)
		ucl_object_unref(root);
	if (parser != NULL)
		ucl_parser_free(parser);
	upb_Arena_Free(t.arena);
	return (ret);
}

/* ---------------------------------------------------------------- */
/* Responses								*/

int
oe_otlppb_partial(const struct oe_otlppb_defs *d, enum oe_signal sig,
    const void *buf, size_t len, int64_t *rejected, char *msg, size_t msglen)
{
	const upb_MessageDef *md, *psd;
	const upb_FieldDef *f;
	upb_Message *resp;
	const upb_Message *ps;
	upb_MessageValue v;
	upb_Arena *arena;
	int ret;

	*rejected = 0;
	msg[0] = '\0';
	if ((arena = upb_Arena_New()) == NULL)
		return (-1);
	ret = -1;
	md = d->response[sig];
	resp = upb_Message_New(upb_MessageDef_MiniTable(md), arena);
	if (resp == NULL || upb_Decode(buf, len, resp,
	    upb_MessageDef_MiniTable(md), NULL, 0, arena) !=
	    kUpb_DecodeStatus_Ok)
		goto out;
	ret = 0;
	/* Export*ServiceResponse.partial_success = 1. */
	f = upb_MessageDef_FindFieldByNumber(md, 1);
	if (!upb_Message_HasFieldByDef(resp, f))
		goto out;
	ps = upb_Message_GetFieldByDef(resp, f).msg_val;
	psd = upb_FieldDef_MessageSubDef(f);
	/* rejected_<items> = 1, error_message = 2. */
	*rejected = upb_Message_GetFieldByDef(ps,
	    upb_MessageDef_FindFieldByNumber(psd, 1)).int64_val;
	v = upb_Message_GetFieldByDef(ps,
	    upb_MessageDef_FindFieldByNumber(psd, 2));
	snprintf(msg, msglen, "%.*s", (int)v.str_val.size, v.str_val.data);
out:
	upb_Arena_Free(arena);
	return (ret);
}

/*
 * A minimal protobuf wire reader for google.rpc.Status, which is not
 * part of opentelemetry-proto.
 */
struct wire {
	const unsigned char *p, *end;
};

static int
wire_varint(struct wire *w, uint64_t *v)
{
	int shift;

	*v = 0;
	for (shift = 0; shift < 64; shift += 7) {
		if (w->p >= w->end)
			return (-1);
		*v |= (uint64_t)(*w->p & 0x7f) << shift;
		if ((*w->p++ & 0x80) == 0)
			return (0);
	}
	return (-1);
}

/*
 * The next field: its number, wire type and, for length-delimited
 * fields, the payload; varints come back in *v.  Other wire types are
 * skipped.
 */
static int
wire_field(struct wire *w, uint32_t *num, int *type, uint64_t *v,
    struct wire *payload)
{
	uint64_t key;

	if (wire_varint(w, &key) != 0 || (key >> 3) == 0 ||
	    (key >> 3) > UINT32_MAX)
		return (-1);
	*num = (uint32_t)(key >> 3);
	*type = (int)(key & 7);
	switch (*type) {
	case 0:
		return (wire_varint(w, v));
	case 1:
	case 5:
		if ((size_t)(w->end - w->p) < (*type == 1 ? 8u : 4u))
			return (-1);
		w->p += *type == 1 ? 8 : 4;
		return (0);
	case 2:
		if (wire_varint(w, v) != 0 || *v > (uint64_t)(w->end - w->p))
			return (-1);
		payload->p = w->p;
		payload->end = w->p + *v;
		w->p += *v;
		return (0);
	default:
		return (-1);
	}
}

/* google.rpc.RetryInfo { google.protobuf.Duration retry_delay = 1; } */
static int
retry_info(struct wire w, double *delay)
{
	struct wire dur, ign;
	uint64_t v;
	uint32_t num;
	int type;
	int64_t secs = 0;
	int32_t nanos = 0;

	*delay = 0;
	while (w.p < w.end) {
		if (wire_field(&w, &num, &type, &v, &dur) != 0)
			return (-1);
		if (num != 1 || type != 2)
			continue;
		while (dur.p < dur.end) {
			if (wire_field(&dur, &num, &type, &v, &ign) != 0)
				return (-1);
			if (num == 1 && type == 0)
				secs = (int64_t)v;
			else if (num == 2 && type == 0)
				nanos = (int32_t)v;
		}
	}
	if (secs < 0 || nanos < 0)
		return (-1);
	*delay = (double)secs + (double)nanos / 1e9;
	return (0);
}

int
oe_rpc_status_parse(const void *buf, size_t len, struct oe_rpc_status *st)
{
	static const char retry_type[] = "/google.rpc.RetryInfo";
#define	RETRY_TYPE_LEN	(sizeof(retry_type) - 1)
	struct wire w, pl, any, val, ign;
	uint64_t v;
	uint32_t num, anum;
	int type, atype, is_retry;
	size_t tlen;

	memset(st, 0, sizeof(*st));
	st->retry_delay = -1;
	w.p = buf;
	w.end = w.p + len;
	while (w.p < w.end) {
		if (wire_field(&w, &num, &type, &v, &pl) != 0)
			return (-1);
		if (num == 1 && type == 0)
			st->code = (int32_t)v;
		else if (num == 2 && type == 2)
			snprintf(st->message, sizeof(st->message), "%.*s",
			    (int)(pl.end - pl.p), (const char *)pl.p);
		else if (num == 3 && type == 2) {
			/* google.protobuf.Any { type_url = 1; value = 2; } */
			any = pl;
			is_retry = 0;
			val.p = val.end = NULL;
			while (any.p < any.end) {
				if (wire_field(&any, &anum, &atype, &v,
				    &ign) != 0)
					return (-1);
				if (anum == 1 && atype == 2) {
					tlen = (size_t)(ign.end - ign.p);
					is_retry = tlen >= RETRY_TYPE_LEN &&
					    memcmp(ign.end - RETRY_TYPE_LEN,
					    retry_type, RETRY_TYPE_LEN) == 0;
				} else if (anum == 2 && atype == 2)
					val = ign;
			}
			if (is_retry && retry_info(val, &st->retry_delay) != 0)
				return (-1);
		}
	}
	return (0);
}
