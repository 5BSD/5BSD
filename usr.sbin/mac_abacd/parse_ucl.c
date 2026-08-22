/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * UCL Policy Parser
 *
 * Parses ABAC policy files in UCL format. Also supports JSON since
 * UCL is a superset of JSON.
 *
 * Policy file format:
 *
 * # Set enforcement mode: disabled, permissive, enforcing
 * mode = "enforcing";
 *
 * # Rules are evaluated in order (first match wins)
 * rules = [
 *     {
 *         action = "deny";
 *         operations = ["exec"];
 *         object = { type = "untrusted"; };
 *     },
 *     {
 *         action = "allow";
 *         operations = ["read", "write"];
 *         subject = { domain = "web"; };
 *         object = { domain = "web"; };
 *     },
 *     {
 *         action = "allow";
 *         operations = ["exec"];
 *         subject = { type = "admin"; };
 *         subj_ctx = { jail = "host"; };
 *     },
 *     {
 *         action = "deny";
 *         operations = ["debug"];
 *         obj_ctx = { sandboxed = true; };
 *     },
 * ];
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include "mac_abacd.h"

/* Action name to value mapping */
static const struct {
	const char	*name;
	uint8_t		 action;
} action_map[] = {
	{ "allow",	ABAC_ACTION_ALLOW },
	{ "deny",	ABAC_ACTION_DENY },
	{ NULL,		0 }
};

static bool verbose_mode = false;

static void
log_verbose(const char *fmt, ...)
{
	va_list ap;

	if (!verbose_mode)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

/*
 * Parse operation list (array of strings or single string)
 */
static int
parse_operations(const ucl_object_t *obj, uint32_t *operations)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it = NULL;
	uint32_t op;
	const char *str;

	*operations = 0;
	if (obj == NULL) {
		*operations = ABAC_OP_ALL;
		return (0);
	}

	if (ucl_object_type(obj) == UCL_STRING) {
		str = ucl_object_tostring(obj);
		if (mac_abacd_parse_operations(str, &op) != 0)
			return (-1);
		*operations = op;
	} else if (ucl_object_type(obj) == UCL_ARRAY) {
		while ((elem = ucl_object_iterate(obj, &it, true)) != NULL) {
			if (ucl_object_type(elem) != UCL_STRING)
				return (-1);
			str = ucl_object_tostring(elem);
			if (mac_abacd_parse_operations(str, &op) != 0)
				return (-1);
			*operations |= op;
		}
	} else
		return (-1);

	return (*operations == 0 ? -1 : 0);
}

/*
 * Parse action string
 */
static int
parse_action(const ucl_object_t *obj, uint8_t *action)
{
	const char *str;
	int i;

	if (obj == NULL || ucl_object_type(obj) != UCL_STRING)
		return (-1);

	str = ucl_object_tostring(obj);
	for (i = 0; action_map[i].name != NULL; i++) {
		if (strcasecmp(str, action_map[i].name) == 0) {
			*action = action_map[i].action;
			return (0);
		}
	}

	return (-1);
}

/*
 * Parse a pattern (subject or object)
 *
 * The new abac_pattern_io uses a simple string field (vp_pattern)
 * that supports arbitrary key=value pairs. We build the string from
 * UCL object keys.
 *
 * UCL format (supports arbitrary keys):
 *   subject = { type = "app"; domain = "web"; sensitivity = "secret"; }
 *   object = { compartment = "hr"; level = "high"; }
 *   subject = "*";  -- wildcard
 *   object = "type=app,domain=web";  -- string form
 *
 * The pattern string format is: "key1=val1,key2=val2,..."
 */
static int
parse_pattern(const ucl_object_t *obj, struct abac_pattern_io *pattern)
{
	const ucl_object_t *val;
	ucl_object_iter_t it = NULL;
	const char *key, *str;
	size_t keylen, strlen_value, needed, pos;
	bool first;
	bool negate = false;

	memset(pattern, 0, sizeof(*pattern));

	if (obj == NULL) {
		strlcpy(pattern->vp_pattern, "*", sizeof(pattern->vp_pattern));
		return (0);
	}

	/* Handle string form: "*" or "type=app,domain=web" */
	if (ucl_object_type(obj) == UCL_STRING) {
		str = ucl_object_tostring(obj);
		return (mac_abacd_parse_pattern(str, pattern));
	}

	if (ucl_object_type(obj) != UCL_OBJECT)
		return (-1);

	/* Check for negate flag in object */
	val = ucl_object_lookup(obj, "negate");
	if (val != NULL) {
		if (ucl_object_type(val) != UCL_BOOLEAN)
			return (-1);
		negate = ucl_object_toboolean(val);
	}

	/* Build pattern string from all key=value pairs in the object */
	pos = 0;
	first = true;

	while ((val = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(val);

		/* Skip special keys */
		if (key != NULL && strcmp(key, "negate") == 0)
			continue;

		if (key == NULL || ucl_object_type(val) != UCL_STRING)
			return (-1);

		str = ucl_object_tostring(val);
		keylen = strlen(key);
		strlen_value = strlen(str);
		needed = keylen + 1 + strlen_value + (first ? 0 : 1);
		if (needed >= sizeof(pattern->vp_pattern) - pos)
			return (-1);
		if (!first)
			pattern->vp_pattern[pos++] = ',';
		first = false;
		memcpy(pattern->vp_pattern + pos, key, keylen);
		pos += keylen;
		pattern->vp_pattern[pos++] = '=';
		memcpy(pattern->vp_pattern + pos, str, strlen_value);
		pos += strlen_value;
		pattern->vp_pattern[pos] = '\0';
	}

	/* If pattern is empty, treat as wildcard */
	if (pattern->vp_pattern[0] == '\0') {
		strlcpy(pattern->vp_pattern, "*", sizeof(pattern->vp_pattern));
	}

	if (mac_abacd_parse_pattern(pattern->vp_pattern, pattern) != 0)
		return (-1);
	if (negate)
		pattern->vp_flags |= ABAC_MATCH_NEGATE;
	return (0);
}

/*
 * Parse context constraints
 * Returns 0 on success, -1 on error.
 */
static int
parse_context(const ucl_object_t *obj, struct abac_context_io *ctx)
{
	const ucl_object_t *val, *entry;
	const ucl_object_t *uid_val, *ruid_val;
	ucl_object_iter_t it = NULL;
	const char *str;
	const char *key;
	int64_t number;

	memset(ctx, 0, sizeof(*ctx));

	if (obj == NULL)
		return (0);
	if (ucl_object_type(obj) != UCL_OBJECT)
		return (-1);

	while ((entry = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(entry);
		if (key == NULL || (strcmp(key, "jail") != 0 &&
		    strcmp(key, "sandboxed") != 0 && strcmp(key, "tty") != 0 &&
		    strcmp(key, "uid") != 0 && strcmp(key, "gid") != 0 &&
		    strcmp(key, "ruid") != 0)) {
			mac_abacd_log(LOG_ERR, "unknown context key: %s",
			    key != NULL ? key : "(null)");
			return (-1);
		}
	}

	/* Check for conflicting uid and ruid */
	uid_val = ucl_object_lookup(obj, "uid");
	ruid_val = ucl_object_lookup(obj, "ruid");
	if (uid_val != NULL && ruid_val != NULL) {
		mac_abacd_log(LOG_ERR,
		    "uid and ruid cannot be used together (both use vc_uid field)");
		return (-1);
	}

	/* jail: "host", "any", or jail ID */
	val = ucl_object_lookup(obj, "jail");
	if (val != NULL) {
		ctx->vc_flags |= ABAC_CTX_JAIL;
		if (ucl_object_type(val) == UCL_STRING) {
			str = ucl_object_tostring(val);
			if (strcasecmp(str, "host") == 0)
				ctx->vc_jail_check = 0;
			else if (strcasecmp(str, "any") == 0)
				ctx->vc_jail_check = -1;
			else {
				char *endptr;
				long jid;
				errno = 0;
				jid = strtol(str, &endptr, 10);
				if (errno != 0 || *endptr != '\0' || jid < 0) {
					mac_abacd_log(LOG_WARNING,
					    "invalid jail ID: %s", str);
					return (-1);
				} else {
					if (jid > INT32_MAX)
						return (-1);
					ctx->vc_jail_check = (int)jid;
				}
			}
		} else if (ucl_object_type(val) == UCL_INT) {
			number = ucl_object_toint(val);
			if (number < 0 || number > INT32_MAX)
				return (-1);
			ctx->vc_jail_check = (int32_t)number;
		} else
			return (-1);
	}

	/* sandboxed: true/false */
	val = ucl_object_lookup(obj, "sandboxed");
	if (val != NULL) {
		if (ucl_object_type(val) != UCL_BOOLEAN)
			return (-1);
		ctx->vc_flags |= ABAC_CTX_CAP_SANDBOXED;
		ctx->vc_cap_sandboxed = ucl_object_toboolean(val);
	}

	/* tty: true/false */
	val = ucl_object_lookup(obj, "tty");
	if (val != NULL) {
		if (ucl_object_type(val) != UCL_BOOLEAN)
			return (-1);
		ctx->vc_flags |= ABAC_CTX_HAS_TTY;
		ctx->vc_has_tty = ucl_object_toboolean(val);
	}

	/* uid */
	if (uid_val != NULL) {
		if (ucl_object_type(uid_val) != UCL_INT)
			return (-1);
		number = ucl_object_toint(uid_val);
		if (number < 0 || (uint64_t)number > UINT32_MAX)
			return (-1);
		ctx->vc_flags |= ABAC_CTX_UID;
		ctx->vc_uid = (uint32_t)number;
	}

	/* gid */
	val = ucl_object_lookup(obj, "gid");
	if (val != NULL) {
		if (ucl_object_type(val) != UCL_INT)
			return (-1);
		number = ucl_object_toint(val);
		if (number < 0 || (uint64_t)number > UINT32_MAX)
			return (-1);
		ctx->vc_flags |= ABAC_CTX_GID;
		ctx->vc_gid = (uint32_t)number;
	}

	/* ruid (real uid) */
	if (ruid_val != NULL) {
		if (ucl_object_type(ruid_val) != UCL_INT)
			return (-1);
		number = ucl_object_toint(ruid_val);
		if (number < 0 || (uint64_t)number > UINT32_MAX)
			return (-1);
		ctx->vc_flags |= ABAC_CTX_RUID;
		ctx->vc_uid = (uint32_t)number;
	}

	return (0);
}

/*
 * Parse a single rule object
 */
static int
parse_rule(const ucl_object_t *obj, struct abac_rule_io *rule,
    uint32_t source_id)
{
	const ucl_object_t *val, *entry;
	ucl_object_iter_t it = NULL;
	const char *key;

	memset(rule, 0, sizeof(*rule));
	rule->vr_id = source_id;

	if (obj == NULL || ucl_object_type(obj) != UCL_OBJECT)
		return (-1);
	while ((entry = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(entry);
		if (key == NULL || (strcmp(key, "set") != 0 &&
		    strcmp(key, "action") != 0 &&
		    strcmp(key, "operations") != 0 &&
		    strcmp(key, "subject") != 0 && strcmp(key, "object") != 0 &&
		    strcmp(key, "subj_ctx") != 0 &&
		    strcmp(key, "obj_ctx") != 0)) {
			mac_abacd_log(LOG_ERR, "unknown rule key: %s",
			    key != NULL ? key : "(null)");
			return (-1);
		}
	}

	/* set (optional, defaults to 0) */
	val = ucl_object_lookup(obj, "set");
	if (val != NULL) {
		if (ucl_object_type(val) != UCL_INT) {
			mac_abacd_log(LOG_ERR, "rule %u: set must be an integer",
			    rule->vr_id);
			return (-1);
		}
		int64_t set_val = ucl_object_toint(val);
		if (set_val < 0 || set_val >= ABAC_MAX_SETS) {
			mac_abacd_log(LOG_ERR, "rule %u: invalid set %jd",
			    rule->vr_id, (intmax_t)set_val);
			return (-1);
		}
		rule->vr_set = (uint16_t)set_val;
	} else {
		rule->vr_set = ABAC_SET_DEFAULT;
	}

	/* action (required) */
	val = ucl_object_lookup(obj, "action");
	if (parse_action(val, &rule->vr_action) < 0) {
		mac_abacd_log(LOG_ERR, "rule %u: invalid or missing 'action'",
		    rule->vr_id);
		return (-1);
	}

	/* operations */
	val = ucl_object_lookup(obj, "operations");
	if (parse_operations(val, &rule->vr_operations) < 0) {
		mac_abacd_log(LOG_ERR, "rule %u: invalid operations",
		    rule->vr_id);
		return (-1);
	}

	/* subject pattern */
	val = ucl_object_lookup(obj, "subject");
	if (parse_pattern(val, &rule->vr_subject) < 0) {
		mac_abacd_log(LOG_ERR, "rule %u: invalid subject pattern",
		    rule->vr_id);
		return (-1);
	}

	/* object pattern */
	val = ucl_object_lookup(obj, "object");
	if (parse_pattern(val, &rule->vr_object) < 0) {
		mac_abacd_log(LOG_ERR, "rule %u: invalid object pattern",
		    rule->vr_id);
		return (-1);
	}

	/* subject context constraints */
	val = ucl_object_lookup(obj, "subj_ctx");
	if (parse_context(val, &rule->vr_subj_context) < 0)
		return (-1);

	/* object context constraints */
	val = ucl_object_lookup(obj, "obj_ctx");
	if (parse_context(val, &rule->vr_obj_context) < 0)
		return (-1);

	log_verbose("  rule %u: action=%d ops=0x%x subj_flags=0x%x obj_flags=0x%x",
	    rule->vr_id, rule->vr_action, rule->vr_operations,
	    rule->vr_subject.vp_flags, rule->vr_object.vp_flags);

	return (0);
}

/*
 * Parse mode setting
 */
static int
decode_mode(const ucl_object_t *obj, bool *present, int *mode)
{
	const char *str;

	*present = false;
	if (obj == NULL)
		return (0);
	if (ucl_object_type(obj) != UCL_STRING)
		return (-1);
	*present = true;

	str = ucl_object_tostring(obj);
	if (strcasecmp(str, "disabled") == 0)
		*mode = ABAC_MODE_DISABLED;
	else if (strcasecmp(str, "permissive") == 0)
		*mode = ABAC_MODE_PERMISSIVE;
	else if (strcasecmp(str, "enforcing") == 0)
		*mode = ABAC_MODE_ENFORCING;
	else {
		mac_abacd_log(LOG_ERR, "invalid mode: %s", str);
		return (-1);
	}

	return (0);
}

/*
 * Parse default_policy setting
 */
static int
decode_default_policy(const ucl_object_t *obj, bool *present, int *policy)
{
	const char *str;

	*present = false;
	if (obj == NULL)
		return (0);
	if (ucl_object_type(obj) != UCL_STRING)
		return (-1);
	*present = true;

	str = ucl_object_tostring(obj);
	if (strcasecmp(str, "allow") == 0)
		*policy = 0;
	else if (strcasecmp(str, "deny") == 0)
		*policy = 1;
	else {
		mac_abacd_log(LOG_ERR, "invalid default_policy: %s", str);
		return (-1);
	}

	return (0);
}

/*
 * Parse append setting - if true, don't clear existing rules
 */
static int
validate_root(const ucl_object_t *root)
{
	const ucl_object_t *entry;
	ucl_object_iter_t it = NULL;
	const char *key;

	if (root == NULL || ucl_object_type(root) != UCL_OBJECT)
		return (-1);
	while ((entry = ucl_object_iterate(root, &it, true)) != NULL) {
		key = ucl_object_key(entry);
		if (key == NULL || (strcmp(key, "mode") != 0 &&
		    strcmp(key, "default_policy") != 0 &&
		    strcmp(key, "rules") != 0)) {
			mac_abacd_log(LOG_ERR, "unknown policy key: %s",
			    key != NULL ? key : "(null)");
			return (-1);
		}
	}
	return (0);
}

/*
 * Parse rules with callback - for mac_abac_ctl to build packed buffers
 */
static int
parse_rules_with_callback(const ucl_object_t *obj,
    abac_rule_callback_t callback, void *ctx)
{
	const ucl_object_t *rule_obj;
	ucl_object_iter_t it = NULL;
	struct abac_rule_io rule;
	int count = 0;
	int errors = 0;

	if (obj == NULL || ucl_object_type(obj) != UCL_ARRAY) {
		mac_abacd_log(LOG_ERR, "policy requires a 'rules' array");
		return (-1);
	}

	while ((rule_obj = ucl_object_iterate(obj, &it, true)) != NULL) {
		if (parse_rule(rule_obj, &rule, (uint32_t)count + 1) < 0) {
			errors++;
			continue;
		}

		if (callback(&rule, ctx) < 0) {
			errors++;
			continue;
		}

		count++;
	}

	mac_abacd_log(LOG_INFO, "parsed %d rules (%d errors)", count, errors);

	return (errors > 0 ? -1 : 0);
}

/*
 * Parse UCL file with callback for each rule
 * This is used by mac_abac_ctl which needs to build packed rule buffers
 * rather than sending rules directly to kernel.
 */
int
mac_abacd_compile_ucl(const char *path, bool verbose,
    abac_rule_callback_t callback, void *ctx,
    struct mac_abac_policy_settings *settings)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *obj;
	const char *errmsg;
	int error = 0;

	verbose_mode = verbose;
	if (path == NULL || callback == NULL || settings == NULL)
		return (-1);
	memset(settings, 0, sizeof(*settings));

	log_verbose("parsing UCL file: %s", path);

	parser = ucl_parser_new(UCL_PARSER_KEY_LOWERCASE);
	if (parser == NULL) {
		mac_abacd_log(LOG_ERR, "ucl_parser_new failed");
		return (-1);
	}

	/* Enable include support */
	ucl_parser_set_filevars(parser, path, true);

	if (!ucl_parser_add_file(parser, path)) {
		errmsg = ucl_parser_get_error(parser);
		mac_abacd_log(LOG_ERR, "parse error: %s", errmsg ? errmsg : "unknown");
		ucl_parser_free(parser);
		return (-1);
	}

	root = ucl_parser_get_object(parser);
	ucl_parser_free(parser);

	if (root == NULL) {
		mac_abacd_log(LOG_ERR, "failed to get UCL object");
		return (-1);
	}
	if (validate_root(root) != 0) {
		ucl_object_unref(root);
		return (-1);
	}

	obj = ucl_object_lookup(root, "mode");
	if (decode_mode(obj, &settings->has_mode, &settings->mode) < 0)
		error = -1;
	obj = ucl_object_lookup(root, "default_policy");
	if (decode_default_policy(obj, &settings->has_default_policy,
	    &settings->default_policy) < 0)
		error = -1;

	/* Do not invoke callbacks for a document with invalid global settings. */
	obj = ucl_object_lookup(root, "rules");
	if (error == 0 && parse_rules_with_callback(obj, callback, ctx) < 0)
		error = -1;

	ucl_object_unref(root);

	return (error);
}
