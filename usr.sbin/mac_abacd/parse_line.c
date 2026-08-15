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
 *   action operations subject [ctx:...] -> object [ctx:...] [=> newlabel] [set N]
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
 *   transition exec type=user -> type=setuid,name=su => type=admin
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
	size_t i = 0;

	s = skip_ws(s);
	while (*s && !isspace((unsigned char)*s) && i < buflen - 1) {
		buf[i++] = *s++;
	}
	buf[i] = '\0';

	return (s);
}

/*
 * Parse action: allow, deny, transition
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
	if (strcasecmp(word, "transition") == 0) {
		*action = ABAC_ACTION_TRANSITION;
		return (0);
	}
	return (-1);
}

/*
 * Parse operations: exec, read, write, exec,read,write, all, *
 */
static int
parse_operations(const char *word, uint32_t *ops)
{
	char buf[256];
	char *p, *tok;

	*ops = 0;
	strlcpy(buf, word, sizeof(buf));

	for (tok = strtok_r(buf, ",", &p); tok != NULL;
	     tok = strtok_r(NULL, ",", &p)) {
		if (strcasecmp(tok, "exec") == 0)
			*ops |= ABAC_OP_EXEC;
		else if (strcasecmp(tok, "read") == 0)
			*ops |= ABAC_OP_READ;
		else if (strcasecmp(tok, "write") == 0)
			*ops |= ABAC_OP_WRITE;
		else if (strcasecmp(tok, "mmap") == 0)
			*ops |= ABAC_OP_MMAP;
		else if (strcasecmp(tok, "link") == 0)
			*ops |= ABAC_OP_LINK;
		else if (strcasecmp(tok, "rename") == 0)
			*ops |= ABAC_OP_RENAME;
		else if (strcasecmp(tok, "unlink") == 0)
			*ops |= ABAC_OP_UNLINK;
		else if (strcasecmp(tok, "chdir") == 0)
			*ops |= ABAC_OP_CHDIR;
		else if (strcasecmp(tok, "stat") == 0)
			*ops |= ABAC_OP_STAT;
		else if (strcasecmp(tok, "readdir") == 0)
			*ops |= ABAC_OP_READDIR;
		else if (strcasecmp(tok, "create") == 0)
			*ops |= ABAC_OP_CREATE;
		else if (strcasecmp(tok, "setextattr") == 0)
			*ops |= ABAC_OP_SETEXTATTR;
		else if (strcasecmp(tok, "getextattr") == 0)
			*ops |= ABAC_OP_GETEXTATTR;
		else if (strcasecmp(tok, "lookup") == 0)
			*ops |= ABAC_OP_LOOKUP;
		else if (strcasecmp(tok, "open") == 0)
			*ops |= ABAC_OP_OPEN;
		else if (strcasecmp(tok, "access") == 0)
			*ops |= ABAC_OP_ACCESS;
		else if (strcasecmp(tok, "debug") == 0)
			*ops |= ABAC_OP_DEBUG;
		else if (strcasecmp(tok, "signal") == 0)
			*ops |= ABAC_OP_SIGNAL;
		else if (strcasecmp(tok, "sched") == 0)
			*ops |= ABAC_OP_SCHED;
		else if (strcasecmp(tok, "connect") == 0)
			*ops |= ABAC_OP_CONNECT;
		else if (strcasecmp(tok, "bind") == 0)
			*ops |= ABAC_OP_BIND;
		else if (strcasecmp(tok, "listen") == 0)
			*ops |= ABAC_OP_LISTEN;
		else if (strcasecmp(tok, "accept") == 0)
			*ops |= ABAC_OP_ACCEPT;
		else if (strcasecmp(tok, "send") == 0)
			*ops |= ABAC_OP_SEND;
		else if (strcasecmp(tok, "receive") == 0)
			*ops |= ABAC_OP_RECEIVE;
		else if (strcasecmp(tok, "deliver") == 0)
			*ops |= ABAC_OP_DELIVER;
		else if (strcasecmp(tok, "wait") == 0)
			*ops |= ABAC_OP_WAIT;
		else if (strcasecmp(tok, "mprotect") == 0)
			*ops |= ABAC_OP_MPROTECT;
		else if (strcasecmp(tok, "audit") == 0)
			*ops |= ABAC_OP_AUDIT;
		else if (strcasecmp(tok, "all") == 0 || strcmp(tok, "*") == 0)
			*ops |= ABAC_OP_ALL;
		else
			return (-1);
	}

	if (*ops == 0)
		*ops = ABAC_OP_ALL;

	return (0);
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
static int
parse_pattern(const char *word, struct abac_pattern_io *pattern)
{
	const char *pattern_start;

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

	/* Store the pattern string directly - kernel will parse it */
	if (strlen(pattern_start) >= sizeof(pattern->vp_pattern)) {
		fprintf(stderr, "pattern too long: %s\n", word);
		return (-1);
	}

	strlcpy(pattern->vp_pattern, pattern_start, sizeof(pattern->vp_pattern));

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

	strlcpy(buf, word + 4, sizeof(buf));

	/* Empty ctx: is an error */
	if (buf[0] == '\0') {
		fprintf(stderr, "empty context constraint\n");
		return (-1);
	}

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
			ctx->vc_flags |= ABAC_CTX_JAIL;
			if (strcasecmp(val, "host") == 0)
				ctx->vc_jail_check = 0;
			else if (strcasecmp(val, "any") == 0)
				ctx->vc_jail_check = -1;
			else {
				errno = 0;
				num = strtol(val, &endptr, 10);
				if (errno != 0 || *endptr != '\0' || num < 0) {
					fprintf(stderr, "invalid jail value: %s\n", val);
					return (-1);
				}
				ctx->vc_jail_check = (int)num;
			}
		} else if (strcasecmp(key, "sandboxed") == 0) {
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
			if (ctx->vc_flags & ABAC_CTX_RUID) {
				fprintf(stderr, "uid and ruid cannot be used together (both use vc_uid field)\n");
				return (-1);
			}
			ctx->vc_flags |= ABAC_CTX_UID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0) {
				fprintf(stderr, "invalid uid: %s\n", val);
				return (-1);
			}
			ctx->vc_uid = (uint32_t)num;
		} else if (strcasecmp(key, "gid") == 0) {
			ctx->vc_flags |= ABAC_CTX_GID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0) {
				fprintf(stderr, "invalid gid: %s\n", val);
				return (-1);
			}
			ctx->vc_gid = (uint32_t)num;
		} else if (strcasecmp(key, "ruid") == 0) {
			if (ctx->vc_flags & ABAC_CTX_UID) {
				fprintf(stderr, "uid and ruid cannot be used together (both use vc_uid field)\n");
				return (-1);
			}
			ctx->vc_flags |= ABAC_CTX_RUID;
			errno = 0;
			num = strtol(val, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || num < 0) {
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
 * Format: action operations subject [ctx:...] -> object [ctx:...] [=> newlabel]
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
	char word[ABAC_PATTERN_MAX_LEN];
	const char *p;
	bool got_arrow = false;
	bool got_object = false;
	bool got_subj_ctx = false;
	bool got_obj_ctx = false;

	memset(rule, 0, sizeof(*rule));
	rule->vr_id = next_rule_id++;

	p = skip_ws(line);

	/* Skip empty lines and comments */
	if (*p == '\0' || *p == '#')
		return (1);	/* Not an error, just skip */

	/* Action */
	p = parse_word(p, word, sizeof(word));
	if (parse_action(word, &rule->vr_action) < 0) {
		fprintf(stderr, "invalid action: %s\n", word);
		return (-1);
	}

	/* Operations */
	p = parse_word(p, word, sizeof(word));
	if (parse_operations(word, &rule->vr_operations) < 0) {
		fprintf(stderr, "invalid operations: %s\n", word);
		return (-1);
	}

	/* Subject pattern */
	p = parse_word(p, word, sizeof(word));
	if (parse_pattern(word, &rule->vr_subject) < 0) {
		fprintf(stderr, "invalid subject pattern: %s\n", word);
		return (-1);
	}

	/*
	 * Now parse remaining tokens:
	 * - "->" separates subject from object
	 * - "=>" introduces transition label
	 * - ctx: before -> applies to subject
	 * - ctx: after -> applies to object
	 */
	p = skip_ws(p);
	while (*p != '\0') {
		p = parse_word(p, word, sizeof(word));
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
			if (word[0] == '\0') {
				fprintf(stderr, "missing object pattern after '->'\n");
				return (-1);
			}
			if (parse_pattern(word, &rule->vr_object) < 0) {
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

		} else if (strcmp(word, "=>") == 0) {
			/* Transition label */
			if (!got_arrow) {
				fprintf(stderr, "'=>' must appear after '->'\n");
				return (-1);
			}
			p = parse_word(p, word, sizeof(word));
			if (word[0] == '\0') {
				fprintf(stderr, "missing label after '=>'\n");
				return (-1);
			}
			strlcpy(rule->vr_newlabel, word, sizeof(rule->vr_newlabel));

		} else if (strcasecmp(word, "set") == 0) {
			/* Rule set number */
			char *endptr;
			long set_val;

			p = parse_word(p, word, sizeof(word));
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
