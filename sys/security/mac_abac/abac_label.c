/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC Label Management
 *
 * This file implements label allocation, parsing, and matching for the
 * ABAC MAC policy. Labels are key-value pairs stored in extended
 * attributes and cached in MAC label slots.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>

#include <machine/atomic.h>
#include <vm/uma.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * UMA zone for label allocation
 */
static uma_zone_t abac_zone;

/*
 * Statistics counters - accessed atomically via atomic_add_64()
 */
static uint64_t abac_labels_allocated;
static uint64_t abac_labels_freed;
static uint64_t abac_parse_errors;

SYSCTL_DECL(_security_mac_mac_abac);
SYSCTL_UQUAD(_security_mac_mac_abac, OID_AUTO, labels_allocated, CTLFLAG_RD,
    &abac_labels_allocated, 0, "Total labels allocated");
SYSCTL_UQUAD(_security_mac_mac_abac, OID_AUTO, labels_freed, CTLFLAG_RD,
    &abac_labels_freed, 0, "Total labels freed");
SYSCTL_UQUAD(_security_mac_mac_abac, OID_AUTO, parse_errors, CTLFLAG_RD,
    &abac_parse_errors, 0, "Label parse errors");

/*
 * abac_label_init - Initialize the label subsystem
 *
 * Called during module init to create the UMA zone.
 */
void
abac_label_init(void)
{

	abac_zone = uma_zcreate("abac_label",
	    sizeof(struct abac_label),
	    NULL,	/* ctor */
	    NULL,	/* dtor */
	    NULL,	/* init */
	    NULL,	/* fini */
	    UMA_ALIGN_PTR,
	    0);		/* flags */

	if (abac_zone == NULL) {
		printf("abac: WARNING: unable to create label zone\n");
		return;
	}

	abac_labels_allocated = 0;
	abac_labels_freed = 0;
	abac_parse_errors = 0;

}

/*
 * abac_label_destroy - Destroy the label subsystem
 *
 * Called during module unload.
 *
 * NOTE: We do NOT destroy the UMA zone here because:
 * 1. Labels may still be attached to vnodes/creds that haven't been
 *    destroyed yet (MAC framework calls label_destroy callbacks AFTER
 *    mpo_destroy in some cases)
 * 2. uma_zdestroy() requires the zone to be empty and will panic if not
 *
 * This is why the module uses MPC_LOADTIME_FLAG_NOTLATE (no UNLOADOK) -
 * the module is designed to be loaded at boot and never unloaded.
 * This follows the pattern of mac_biba and mac_lomac.
 */
void
abac_label_destroy(void)
{

	/* Don't destroy the zone - see note above */
}

/*
 * abac_label_alloc - Allocate a new label structure
 *
 * @flags: M_WAITOK or M_NOWAIT
 *
 * Returns a zeroed label structure, or NULL if allocation fails
 * (only possible with M_NOWAIT or if zone not yet initialized).
 */
struct abac_label *
abac_label_alloc(int flags)
{
	struct abac_label *vl;

	/* Zone not initialized yet - can happen during early boot */
	if (abac_zone == NULL)
		return (NULL);

	vl = uma_zalloc(abac_zone, flags | M_ZERO);
	if (vl != NULL)
		atomic_add_64(&abac_labels_allocated, 1);

	return (vl);
}

/*
 * abac_label_free - Free a label structure
 *
 * @vl: Label to free (may be NULL)
 */
void
abac_label_free(struct abac_label *vl)
{

	if (vl == NULL)
		return;

	/* Zone not initialized - shouldn't happen but be safe */
	if (abac_zone == NULL)
		return;

	uma_zfree(abac_zone, vl);
	atomic_add_64(&abac_labels_freed, 1);
}

/*
 * abac_label_hash - Compute a simple hash of a label string
 *
 * Used for quick inequality checks before doing full string comparisons.
 */
uint32_t
abac_label_hash(const char *str, size_t len)
{
	uint32_t hash = 5381;  /* DJB2 hash algorithm seed */
	size_t i;

	if (str == NULL || len == 0)
		return (0);

	for (i = 0; i < len && str[i] != '\0'; i++)
		hash = ((hash << 5) + hash) + (unsigned char)str[i];

	return (hash);
}

/*
 * parse_kv_pair - Parse a single key=value pair into the pairs array
 *
 * @str: String containing "key=value"
 * @len: Length of string
 * @vl: Label structure to populate
 *
 * Returns 0 on success, error code on failure.
 */
static int
parse_kv_pair(const char *str, size_t len, struct abac_label *vl)
{
	struct abac_pair *pair;
	const char *eq;
	size_t keylen, valuelen;

	/* Check if we have room for another pair */
	if (vl->vl_npairs >= ABAC_MAX_PAIRS)
		return (E2BIG);

	/* Find the '=' separator */
	eq = memchr(str, '=', len);
	if (eq == NULL) {
		return (EINVAL);
	}

	keylen = eq - str;
	valuelen = len - keylen - 1;

	/* Validate lengths */
	if (keylen == 0 || keylen >= ABAC_MAX_KEY_LEN)
		return (EINVAL);
	if (valuelen >= ABAC_MAX_VALUE_LEN)
		return (EINVAL);

	/* Store in the next available pair slot */
	pair = &vl->vl_pairs[vl->vl_npairs];

	memcpy(pair->vp_key, str, keylen);
	pair->vp_key[keylen] = '\0';

	memcpy(pair->vp_value, eq + 1, valuelen);
	pair->vp_value[valuelen] = '\0';

	vl->vl_npairs++;

	return (0);
}

/*
 * abac_label_parse - Parse a label string into a label structure
 *
 * @str: Label string in newline-separated format: "key1=val1\nkey2=val2\n"
 * @len: Length of string (not including null terminator)
 * @vl: Label structure to populate (must be zeroed)
 *
 * Returns 0 on success, error code on failure.
 *
 * Example input: "type=system\ndomain=daemon\n"
 */
int
abac_label_parse(const char *str, size_t len, struct abac_label *vl)
{
	const char *p, *end, *nl;
	int error;

	/* Validate inputs */
	if (str == NULL || vl == NULL)
		return (EINVAL);

	/* Empty string is valid - means unlabeled/default */
	if (len == 0) {
		memset(vl, 0, sizeof(*vl));
		return (0);
	}

	if (len > ABAC_MAX_LABEL_LEN) {
		atomic_add_64(&abac_parse_errors, 1);
		return (EINVAL);
	}

	/* Initialize and compute hash */
	vl->vl_hash = abac_label_hash(str, len);
	vl->vl_npairs = 0;
	vl->vl_flags = 0;	/* Clear NEEDS_LOAD after parsing */

	/* Parse newline-separated key=value pairs */
	p = str;
	end = str + len;

	while (p < end) {
		/* Find next newline or end of string */
		nl = memchr(p, '\n', end - p);
		if (nl == NULL)
			nl = end;

		/* Parse this pair (skip empty lines) */
		if (nl > p) {
			error = parse_kv_pair(p, nl - p, vl);
			if (error != 0) {
				atomic_add_64(&abac_parse_errors, 1);
				return (error);
			}
		}

		/* Move past newline */
		p = nl + 1;
	}

	return (0);
}

/*
 * abac_label_copy - Copy a label structure
 *
 * @src: Source label
 * @dst: Destination label (must be allocated)
 */
void
abac_label_copy(const struct abac_label *src, struct abac_label *dst)
{

	if (src == NULL || dst == NULL)
		return;

	memcpy(dst, src, sizeof(*dst));
}

/*
 * abac_label_set_default - Set a label to default values
 *
 * @vl: Label to initialize
 * @is_subject: true for process labels, false for object labels
 */
void
abac_label_set_default(struct abac_label *vl, bool is_subject)
{

	if (vl == NULL)
		return;

	memset(vl, 0, sizeof(*vl));

	/*
	 * Both subjects (processes) and objects (files) get the same
	 * default label: type=unlabeled
	 *
	 * This is explicit about "not classified yet" and allows rules like:
	 *   deny exec type=unlabeled -> *   (unlabeled procs can't exec)
	 *   deny exec * -> type=unlabeled   (can't exec unlabeled files)
	 */
	(void)is_subject;  /* Same default for both */
	vl->vl_npairs = 1;
	strlcpy(vl->vl_pairs[0].vp_key, "type",
	    sizeof(vl->vl_pairs[0].vp_key));
	strlcpy(vl->vl_pairs[0].vp_value, "unlabeled",
	    sizeof(vl->vl_pairs[0].vp_value));

	/* Hash the canonical representation */
	vl->vl_hash = abac_label_hash("type=unlabeled\n", 15);
}

/*
 * abac_label_get_value - Get the value for a key in a label
 *
 * @vl: Label to search
 * @key: Key to look up
 *
 * Returns pointer to value string if found, NULL otherwise.
 * The returned pointer is valid as long as the label is not modified.
 */
const char *
abac_label_get_value(const struct abac_label *vl, const char *key)
{
	uint32_t i;

	if (vl == NULL || key == NULL)
		return (NULL);

	for (i = 0; i < vl->vl_npairs; i++) {
		if (strcmp(vl->vl_pairs[i].vp_key, key) == 0)
			return (vl->vl_pairs[i].vp_value);
	}

	return (NULL);
}

/*
 * abac_label_to_string - Convert a label to string representation
 *
 * @vl: Label to convert
 * @buf: Output buffer
 * @buflen: Size of output buffer
 *
 * Returns number of characters written (not including null terminator),
 * or -1 on error.
 */
int
abac_label_to_string(const struct abac_label *vl, char *buf, size_t buflen)
{
	size_t pos = 0;
	uint32_t i;

	if (vl == NULL || buf == NULL || buflen == 0)
		return (-1);

	buf[0] = '\0';

	for (i = 0; i < vl->vl_npairs && pos < buflen - 1; i++) {
		int written = snprintf(buf + pos, buflen - pos, "%s=%s\n",
		    vl->vl_pairs[i].vp_key, vl->vl_pairs[i].vp_value);
		if (written < 0 || (size_t)written >= buflen - pos)
			return (-1);
		pos += written;
	}

	return ((int)pos);
}

/*
 * abac_rule_pattern_parse - Parse pattern string into compact rule pattern
 *
 * @str: Pattern string in comma-separated format "key1=val1,key2=val2,..."
 *       or "*" for wildcard, or "!pattern" for negation
 * @len: Length of string
 * @pattern: Compact rule pattern structure to populate
 *
 * This is similar to abac_pattern_parse but uses the compact
 * abac_rule_pattern structure with smaller limits:
 *   - Max pairs: ABAC_RULE_MAX_PAIRS (8 vs 16)
 *   - Max key: ABAC_RULE_KEY_LEN (64)
 *   - Max value: ABAC_RULE_VALUE_LEN (64 vs 256)
 *
 * Returns 0 on success, error code on failure.
 */
int
abac_rule_pattern_parse(const char *str, size_t len,
    struct abac_rule_pattern *pattern)
{
	const char *p, *end, *comma, *eq;
	size_t keylen, valuelen;
	struct abac_rule_pair *pair;
	uint32_t saved_flags;

	if (str == NULL || pattern == NULL)
		return (EINVAL);

	/*
	 * Save flags before memset - the caller may have already set flags
	 * (e.g., ABAC_MATCH_NEGATE from the syscall argument).
	 */
	saved_flags = pattern->vrp_flags;
	memset(pattern, 0, sizeof(*pattern));
	pattern->vrp_flags = saved_flags;

	/* Check for negation prefix */
	if (len > 0 && str[0] == '!') {
		pattern->vrp_flags |= ABAC_MATCH_NEGATE;
		str++;
		len--;
	}

	/* Empty or "*" means wildcard - match everything */
	if (len == 0 || (len == 1 && str[0] == '*'))
		return (0);

	/* Parse comma-separated key=value pairs */
	p = str;
	end = str + len;

	while (p < end) {
		/* Find next comma or end of string */
		comma = memchr(p, ',', end - p);
		if (comma == NULL)
			comma = end;

		/* Skip empty segments */
		if (comma == p) {
			p = comma + 1;
			continue;
		}

		/* Check pair limit */
		if (pattern->vrp_npairs >= ABAC_RULE_MAX_PAIRS)
			return (E2BIG);

		/* Find '=' separator */
		eq = memchr(p, '=', comma - p);
		if (eq == NULL) {
			return (EINVAL);
		}

		keylen = eq - p;
		valuelen = comma - eq - 1;

		if (keylen == 0 || keylen >= ABAC_RULE_KEY_LEN)
			return (EINVAL);
		if (valuelen >= ABAC_RULE_VALUE_LEN)
			return (EINVAL);

		/* Store this pair */
		pair = &pattern->vrp_pairs[pattern->vrp_npairs];
		memcpy(pair->vrp_key, p, keylen);
		pair->vrp_key[keylen] = '\0';
		memcpy(pair->vrp_value, eq + 1, valuelen);
		pair->vrp_value[valuelen] = '\0';
		pattern->vrp_npairs++;

		p = comma + 1;
	}

	return (0);
}
