/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Trace and span ids.  W3C Trace Context ids are opaque byte strings
 * that must not be all zero.  Random ids come from arc4random(3).
 * Derived ids hash a per-run secret salt, a namespace and a key tuple
 * with SHA-256 and keep the leading bytes, so a probe that ends a
 * span and a probe that ends its child can name the same parent
 * without any shared state, while ids from different runs (different
 * salts) never collide by construction.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "otelexport.h"

/* An all-zero id is invalid; make it non-zero deterministically. */
static void
nonzero(uint8_t *id, size_t len)
{

	if (oe_id_is_zero(id, len))
		id[len - 1] = 1;
}

int
oe_id_is_zero(const uint8_t *id, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (id[i] != 0)
			return (0);
	return (1);
}

void
oe_id_random(uint8_t *id, size_t len)
{

	arc4random_buf(id, len);
	nonzero(id, len);
}

void
oe_id_derive(const uint8_t salt[16], const char *ns, const int64_t *key,
    size_t nkey, uint8_t *id, size_t len)
{
	unsigned char md[EVP_MAX_MD_SIZE], buf[16 + 32 + 8 * 8];
	unsigned int mdlen;
	size_t nslen, off, i, j;
	uint64_t v;

	/*
	 * salt || namespace (NUL-padded to 32) || keys, little-endian.
	 * Namespaces are short constants and key tuples at most eight
	 * words, so the input has a fixed shape and cannot be confused
	 * across namespaces.
	 */
	memset(buf, 0, sizeof(buf));
	memcpy(buf, salt, 16);
	nslen = strlen(ns);
	memcpy(buf + 16, ns, nslen < 32 ? nslen : 32);
	off = 16 + 32;
	for (i = 0; i < nkey && i < 8; i++) {
		v = (uint64_t)key[i];
		for (j = 0; j < 8; j++)
			buf[off++] = (unsigned char)(v >> (8 * j));
	}
	if (EVP_Digest(buf, off, md, &mdlen, EVP_sha256(), NULL) != 1 ||
	    mdlen < len) {
		/* No digest available: fall back to a random id. */
		oe_id_random(id, len);
		return;
	}
	memcpy(id, md, len);
	nonzero(id, len);
}

void
oe_id_hex(const uint8_t *id, size_t len, char *buf)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		buf[2 * i] = hex[id[i] >> 4];
		buf[2 * i + 1] = hex[id[i] & 0xf];
	}
	buf[2 * len] = '\0';
}

/* Two lowercase hex digits; -1 otherwise. */
static int
hexbyte(const char *p)
{
	int i, v, d;

	v = 0;
	for (i = 0; i < 2; i++) {
		if (p[i] >= '0' && p[i] <= '9')
			d = p[i] - '0';
		else if (p[i] >= 'a' && p[i] <= 'f')
			d = p[i] - 'a' + 10;
		else
			return (-1);
		v = v * 16 + d;
	}
	return (v);
}

/*
 * W3C Trace Context traceparent: version "-" trace-id "-" parent-id
 * "-" trace-flags, lowercase hex.  Version ff is invalid; a later
 * version than 00 may carry more fields after the flags, separated
 * by "-", and is read as 00.
 */
int
oe_traceparent_parse(const char *s, size_t len,
    uint8_t trace_id[OE_TRACE_ID_LEN], uint8_t span_id[OE_SPAN_ID_LEN],
    uint8_t *flags)
{
	size_t i;
	int v, ver;

	if (len < 55 || s[2] != '-' || s[35] != '-' || s[52] != '-')
		return (-1);
	if ((ver = hexbyte(s)) < 0 || ver == 0xff ||
	    (ver == 0 && len != 55) || (ver > 0 && len > 55 && s[55] != '-'))
		return (-1);
	for (i = 0; i < OE_TRACE_ID_LEN; i++) {
		if ((v = hexbyte(s + 3 + 2 * i)) < 0)
			return (-1);
		trace_id[i] = (uint8_t)v;
	}
	for (i = 0; i < OE_SPAN_ID_LEN; i++) {
		if ((v = hexbyte(s + 36 + 2 * i)) < 0)
			return (-1);
		span_id[i] = (uint8_t)v;
	}
	if ((v = hexbyte(s + 53)) < 0)
		return (-1);
	*flags = (uint8_t)v;
	if (oe_id_is_zero(trace_id, OE_TRACE_ID_LEN) ||
	    oe_id_is_zero(span_id, OE_SPAN_ID_LEN))
		return (-1);
	return (0);
}
