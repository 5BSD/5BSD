/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * Simple Line Format Parser
 *
 * Parses ABAC rules in a simple line-based format for CLI use.
 *
 * Format:
 *   action operations subject [ctx:...] -> object [ctx:...] [set N]
 *
 * Context placement determines what it applies to:
 *   - ctx: BEFORE '->' applies to subject (caller)
 *   - ctx: AFTER '->' applies to object (target)
 *
 * Set syntax (optional, defaults to 0):
 *   set N              - assign rule to set N (0-65535)
 *
 * Examples:
 *   deny exec * -> type=untrusted
 *   allow read,write domain=web -> domain=web
 *   allow exec type=admin ctx:jail=host -> *
 *   deny debug * ctx:uid=0 -> * ctx:sandboxed=true
 *   deny signal type=user ctx:uid=1000 -> type=system ctx:uid=0
 *   deny exec * -> type=untrusted set 1
 *   allow read domain=app -> domain=app set 100
 *
 * Pattern format:
 *   *                  - match anything
 *   key=value          - match key field
 *   key1=a,key2=b      - match multiple fields (AND)
 *   !pattern           - negate match
 *
 * Context options:
 *   jail=host          - must be on host (not in jail)
 *   jail=any           - must be in any jail
 *   jail=N             - must be in jail with ID N
 *   sandboxed=true     - must be in capability mode (Capsicum)
 *   sandboxed=false    - must NOT be in capability mode
 *   uid=N              - effective UID must be N
 *   gid=N              - effective GID must be N
 *   ruid=N             - real UID must be N
 *   tty=true           - must have controlling terminal
 *
 * Multiple constraints can be combined:
 *   ctx:jail=host,uid=0  - root on host only
 */

#include <sys/param.h>
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mac_abacd.h"

/*
 * Static rule ID counter.
 * Starts at 1000 to reserve IDs 1-999 for kernel-assigned rules.
 */
static uint32_t next_rule_id = 1000;

/*
 * Skip whitespace
 */
static const char *
skip_ws(const char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	return (s);
}

/*
 * Parse a word (non-whitespace sequence)
 */
static const char *
parse_word(const char *s, char *buf, size_t buflen)
{
	const char *start;
	size_t len;

	s = skip_ws(s);
	start = s;
	while (*s && !isspace((unsigned char)*s))
		s++;
	len = (size_t)(s - start);
	if (len >= buflen) {
		buf[0] = '\0';
		return (NULL);
	}
	memcpy(buf, start, len);
	buf[len] = '\0';

	return (s);
}

/*
 * Parse action: allow or deny
 */
static int
parse_action(const char *word, uint8_t *action)
{
	if (strcasecmp(word, "allow") == 0) {
		*action = ABAC_ACTION_ALLOW;
		return (0);
	}
	if (strcasecmp(word, "deny") == 0) {
		*action = ABAC_ACTION_DENY;
		return (0);
	}
	return (-1);
}

/*
 * Parse operations: exec, read, write, exec,read,write, all, *
 */
int
mac_abacd_parse_operations(const char *word, uint32_t *ops)
{
	char buf[256];
	char *p, *tok;
	static const struct {
		const char *name;
		uint32_t operation;
	} operation_names[] = {
#define ABAC_OPERATION_NAME(name, value) { #name, value },
		ABAC_OPERATION_LIST(ABAC_OPERATION_NAME)
#undef ABAC_OPERATION_NAME
	};
	size_t i;
	bool found;

	if (word == NULL || ops == NULL || word[0] == '\0' ||
	    strlen(word) >= sizeof(buf) || word[strlen(word) - 1] == ',' ||
	    strstr(word, ",,") != NULL)
		return (-1);
	*ops = 0;
	strlcpy(buf, word, sizeof(buf));

	for (tok = strtok_r(buf, ",", &p); tok != NULL;
	     tok = strtok_r(NULL, ",", &p)) {
		if (strcasecmp(tok, "all") == 0 || strcmp(tok, "*") == 0) {
			*ops |= ABAC_OP_ALL;
			continue;
		}
		found = false;
		for (i = 0; i < nitems(operation_names); i++) {
			if (strcasecmp(tok, operation_names[i].name) == 0) {
				*ops |= operation_names[i].operation;
				found = true;
				break;
			}
		}
		if (!found)
			return (-1);
	}

	return (*ops == 0 ? -1 : 0);
}

/*
 * Parse a pattern: key1=val1,key2=val2 or * for wildcard
 *
 * The new abac_pattern_io uses a simple string field (vp_pattern)
 * that supports arbitrary key=value pairs. The kernel parses the string.
 *
 * Pattern formats:
 *   *                      - match anything (wildcard)
 *   key1=val1              - must have key1=val1
 *   key1=val1,key2=val2    - must have both
 *   key=*                  - must have key (any value)
 *   !pattern               - negate the match
 */
int
mac_abacd_parse_pattern(const char *word, struct abac_pattern_io *pattern)
{
	char input[ABAC_PATTERN_MAX_LEN];
	const char *pattern_start, *p, *end, *comma, *eq;
	const char *keys[ABAC_RULE_MAX_PAIRS];
	size_t key_lengths[ABAC_RULE_MAX_PAIRS];
	size_t keylen, valuelen, npairs, i;

	if (word == NULL || pattern == NULL ||
	    strlcpy(input, word, sizeof(input)) >= sizeof(input))
		return (-1);
	word = input;
	memset(pattern, 0, sizeof(*pattern));

	/* Wildcard */
	if (strcmp(word, "*") == 0) {
		strlcpy(pattern->vp_pattern, "*", sizeof(pattern->vp_pattern));
		return (0);
	}

	/* Check for negation prefix */
	pattern_start = word;
	if (word[0] == '!') {
		pattern->vp_flags |= ABAC_MATCH_NEGATE;
		pattern_start = word + 1;
	}
	if (pattern_start[0] == '\0')
		return (-1);

	/* Store the pattern string directly - kernel will parse it */
	/* Validate delimiters, limits, and duplicate keys now, not in-kernel. */
	p = pattern_start;
	end = pattern_start + strlen(pattern_start);
	npairs = 0;
	while (p < end) {
		comma = memchr(p, ',', end - p);
		if (comma == NULL)
			comma = end;
		if (comma == p || npairs >= ABAC_RULE_MAX_PAIRS)
			return (-1);
		eq = memchr(p, '=', comma - p);
		if (eq == NULL)
			return (-1);
		keylen = (size_t)(eq - p);
		valuelen = (size_t)(comma - eq - 1);
		if (keylen == 0 || keylen >= ABAC_RULE_KEY_LEN ||
		    valuelen >= ABAC_RULE_VALUE_LEN)
			return (-1);
		for (i = 0; i < npairs; i++) {
			if (key_lengths[i] == keylen &&
			    memcmp(keys[i], p, keylen) == 0)
				return (-1);
		}
		keys[npairs] = p;
		key_lengths[npairs++] = keylen;
		if (comma == end)
			break;
		p = comma + 1;
		if (p == end)
			return (-1);
	}

	strlcpy(pattern->vp_pattern, pattern_start, sizeof(pattern->vp_pattern));

	return (0);
}

int
mac_abacd_validate_label(const char *label)
{
	const char *p, *end, *comma, *eq;
	const char *keys[ABAC_MAX_PAIRS];
	size_t key_lengths[ABAC_MAX_PAIRS];
	size_t keylen, valuelen, npairs, i;

	if (label == NULL || label[0] == '\0' ||
	    strlen(label) + 2 > ABAC_MAX_LABEL_LEN)
		return (-1);
	p = label;
	end = label + strlen(label);
	npairs = 0;
	while (p < end) {
		comma = memchr(p, ',', end - p);
		if (comma == NULL)
			comma = end;
		if (comma == p || npairs >= ABAC_MAX_PAIRS)
			return (-1);
		eq = memchr(p, '=', comma - p);
		if (eq == NULL)
			return (-1);
		keylen = (size_t)(eq - p);
		valuelen = (size_t)(comma - eq - 1);
		if (keylen == 0 || keylen >= ABAC_MAX_KEY_LEN ||
		    valuelen >= ABAC_MAX_VALUE_LEN)
			return (-1);
		for (i = 0; i < npairs; i++) {
			if (key_lengths[i] == keylen &&
			    memcmp(keys[i], p, keylen) == 0)
				return (-1);
		}
		keys[npairs] = p;
		key_lengths[npairs++] = keylen;
		if (comma == end)
			break;
		p = comma + 1;
		if (p == end)
			return (-1);
	}
	return (0);
}

/*
 * Parse context: ctx:jail=host,sandboxed=true
 *
 * Valid keys: jail, sandboxed, tty, uid, gid, ruid
 * Unknown keys are rejected.
 *
 * This function is additive - it merges new constraints into the existing
 * context, allowing multiple ctx: tokens to be combined.
 */
static int
parse_context(const char *word, struct abac_context_io *ctx)
{
	char buf[256];
	char *p, *tok;
	char *key, *val;

	/* Must start with "ctx:" */
	if (strncasecmp(word, "ctx:", 4) != 0)
		return (-1);

	if (strlen(word + 4) >= sizeof(buf))
		return (-1);
	strlcpy(buf, word + 4, sizeof(buf));

	/* Empty ctx: is an error */
	if (buf[0] == '\0') {
		fprintf(stderr, "empty context constraint\n");
		return (-1);
	}
	if (buf[0] == ',' || buf[strlen(buf) - 1] == ',' ||
	    strstr(buf, ",,") != NULL)
		return (-1);

	for (tok = strtok_r(buf, ",", &p); tok != NULL;
	     tok = strtok_r(NULL, ",", &p)) {
		char *endptr;
		long num;

		key = tok;
		val = strchr(tok, '=');
		if (val == NULL) {
			fprintf(stderr, "invalid context syntax (missing '='): %s\n", tok);
			return (-1);
		}
		*val++ = '\0';

		if (strcasecmp(key, "jail") == 0) {
			if ((ctx->vc_flags & ABAC_CTX_JAIL) != 0)
				return (-1);
			ctx->vc_flags |= ABAC_CTX_JAIL;
			if (strcasecmp(val, "host") == 0)
				ctx->vc_jail_check = 0;
			else if (strcasecmp(val, "any") == 0)
				ctx->vc_jail_check = -1;
			else {
				errno = 0;
				num = strtol(val, &endptr, 10);
				if (errno != 0 || *endptr != '\0' || num < 0 ||
				    num > INT32_MAX) {
					fprintf(stderr, "invalid jail value: %s\n", val);
					return (-1);
				}
				ctx->vc_jail_check = (int)num;
			}
		} else if (strcasecmp(key, "sandboxed") == 0) {
			if ((ctx->vc_flags & ABAC_CTX_CAP_SANDBOXED) != 0)
				return (-1);
			ctx->vc_flags |= ABAC_CTX_CAP_SANDBOXED;
			if (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0)
				ctx->vc_cap_sandboxed = 1;
			else if (strcasecmp(val, "false") == 0 || strcmp(val, "0") == 0)
				ctx->vc_cap_sandboxed = 0;
			else {
				fprintf(stderr, "invalid sandboxed value: %s (use true/false)\n", val);
				return (-1);
			}
		} else if (strcasecmp(key, "tty") == 0) {
			if ((ctx->vc_flags & ABAC_CTX_HAS_TTY) != 0)
				return (-1);
			ctx->vc_flags |= ABAC_CTX_HAS_TTY;
			if (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0)
				ctx->vc_has_tty = 1;
			else if (strcasecmp(val, "false") == 0 || strcmp(val, "0") == 0)
				ctx->vc_has_tty = 0;
			else {
				fprintf(stderr, "invalid tty value: %s (use true/false)\n", val);
				return (-1);
			}
		} else if (strcasecmp(key, "uid") == 0) {
			if (ctx->vc_flags & (ABAC_CTX_UID | ABAC_CTX_RUID)) {
				fprintf(stderr, "uid and ruid cannot be used together (both use vc_uid field)\n");
				return (-1);
			}
			ctx->vc_flags |= ABAC_CTX_UID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0 ||
			    (uintmax_t)num > UINT32_MAX) {
				fprintf(stderr, "invalid uid: %s\n", val);
				return (-1);
			}
			ctx->vc_uid = (uint32_t)num;
		} else if (strcasecmp(key, "gid") == 0) {
			if ((ctx->vc_flags & ABAC_CTX_GID) != 0)
				return (-1);
			ctx->vc_flags |= ABAC_CTX_GID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0 ||
			    (uintmax_t)num > UINT32_MAX) {
				fprintf(stderr, "invalid gid: %s\n", val);
				return (-1);
			}
			ctx->vc_gid = (uint32_t)num;
		} else if (strcasecmp(key, "ruid") == 0) {
			if (ctx->vc_flags & (ABAC_CTX_UID | ABAC_CTX_RUID)) {
				fprintf(stderr, "uid and ruid cannot be used together (both use vc_uid field)\n");
				return (-1);
			}
			ctx->vc_flags |= ABAC_CTX_RUID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0 ||
			    (uintmax_t)num > UINT32_MAX) {
				fprintf(stderr, "invalid ruid: %s\n", val);
				return (-1);
			}
			ctx->vc_uid = (uint32_t)num;
		} else {
			fprintf(stderr, "unknown context key: %s\n", key);
			fprintf(stderr, "valid keys: jail, sandboxed, tty, uid, gid, ruid\n");
			return (-1);
		}
	}

	return (0);
}

/*
 * Parse a rule line
 *
 * Format: action operations subject [ctx:...] -> object [ctx:...] [set N]
 *
 * Context placement determines what it applies to:
 *   - ctx: BEFORE '->' applies to subject (caller)
 *   - ctx: AFTER '->' applies to object (target)
 *
 * Examples:
 *   deny exec * -> type=untrusted
 *   deny debug * ctx:jail=any -> type=system
 *   deny debug * -> * ctx:sandboxed=true
 *   deny signal * ctx:uid=0 -> * ctx:jail=host
 *
 * Returns 0 on success, -1 on parse error, 1 for empty/comment line.
 */
int
mac_abacd_parse_line(const char *line, struct abac_rule_io *rule)
{
	char word[ABAC_MAX_LABEL_LEN];
	const char *p;
	bool got_arrow = false;
	bool got_object = false;
	bool got_subj_ctx = false;
	bool got_obj_ctx = false;
	bool got_set = false;

	if (line == NULL || rule == NULL)
		return (-1);
	memset(rule, 0, sizeof(*rule));
	rule->vr_id = next_rule_id++;

	p = skip_ws(line);

	/* Skip empty lines and comments */
	if (*p == '\0' || *p == '#')
		return (1);	/* Not an error, just skip */

	/* Action */
	p = parse_word(p, word, sizeof(word));
	if (p == NULL)
		return (-1);
	if (parse_action(word, &rule->vr_action) < 0) {
		fprintf(stderr, "invalid action: %s\n", word);
		return (-1);
	}

	/* Operations */
	p = parse_word(p, word, sizeof(word));
	if (p == NULL)
		return (-1);
	if (mac_abacd_parse_operations(word, &rule->vr_operations) < 0) {
		fprintf(stderr, "invalid operations: %s\n", word);
		return (-1);
	}

	/* Subject pattern */
	p = parse_word(p, word, sizeof(word));
	if (p == NULL)
		return (-1);
	if (mac_abacd_parse_pattern(word, &rule->vr_subject) < 0) {
		fprintf(stderr, "invalid subject pattern: %s\n", word);
		return (-1);
	}

	/*
	 * Now parse remaining tokens:
	 * - "->" separates subject from object
	 * - ctx: before -> applies to subject
	 * - ctx: after -> applies to object
	 */
	p = skip_ws(p);
	while (*p != '\0') {
		p = parse_word(p, word, sizeof(word));
		if (p == NULL)
			return (-1);
		if (word[0] == '\0')
			break;

		if (strcmp(word, "->") == 0) {
			if (got_arrow) {
				fprintf(stderr, "unexpected second '->'\n");
				return (-1);
			}
			got_arrow = true;

			/* Next word must be object pattern */
			p = parse_word(p, word, sizeof(word));
			if (p == NULL)
				return (-1);
			if (word[0] == '\0') {
				fprintf(stderr, "missing object pattern after '->'\n");
				return (-1);
			}
			if (mac_abacd_parse_pattern(word, &rule->vr_object) < 0) {
				fprintf(stderr, "invalid object pattern: %s\n", word);
				return (-1);
			}
			got_object = true;

		} else if (strncasecmp(word, "ctx:", 4) == 0) {
			/* Position-based context: before -> = subject, after -> = object */
			if (!got_arrow) {
				/* Before arrow - applies to subject */
				if (got_subj_ctx) {
					fprintf(stderr, "duplicate subject ctx: (use comma-separated values)\n");
					return (-1);
				}
				if (parse_context(word, &rule->vr_subj_context) < 0) {
					return (-1);
				}
				got_subj_ctx = true;
			} else {
				/* After arrow - applies to object */
				if (got_obj_ctx) {
					fprintf(stderr, "duplicate object ctx: (use comma-separated values)\n");
					return (-1);
				}
				if (parse_context(word, &rule->vr_obj_context) < 0) {
					return (-1);
				}
				got_obj_ctx = true;
			}

		} else if (strcasecmp(word, "set") == 0) {
			/* Rule set number */
			char *endptr;
			long set_val;

			if (got_set) {
				fprintf(stderr, "duplicate set number\n");
				return (-1);
			}
			p = parse_word(p, word, sizeof(word));
			if (p == NULL)
				return (-1);
			if (word[0] == '\0') {
				fprintf(stderr, "missing set number after 'set'\n");
				return (-1);
			}
			errno = 0;
			set_val = strtol(word, &endptr, 10);
			if (errno != 0 || *endptr != '\0' ||
			    set_val < 0 || set_val >= ABAC_MAX_SETS) {
				fprintf(stderr, "invalid set number: %s\n", word);
				return (-1);
			}
			rule->vr_set = (uint16_t)set_val;
			got_set = true;

		} else {
			/* Unknown token */
			fprintf(stderr, "unexpected token: %s\n", word);
			return (-1);
		}

		p = skip_ws(p);
	}

	/* Validate we got the required parts */
	if (!got_arrow) {
		fprintf(stderr, "missing '->' in rule\n");
		return (-1);
	}
	if (!got_object) {
		fprintf(stderr, "missing object pattern\n");
		return (-1);
	}
	return (0);
}
