/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC Syscall Handlers
 *
 * Handles mac_syscall() operations for rule management:
 * - Rule add/remove/clear/list/load
 * - Test access simulation
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/rwlock.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"
#include "abac_dtrace.h"

/*
 * External rule table (defined in abac_rules.c)
 */
extern struct abac_rule *abac_rules[];
extern int abac_rule_count;
extern int abac_rule_end;
extern struct rwlock abac_rules_lock;
extern uint32_t abac_next_rule_id;
extern uint16_t abac_active_sets[];
extern uint16_t abac_active_set_count;

static bool
abac_packed_string_valid(const char *str, uint16_t len)
{
	const char *nul;

	if (str == NULL || len == 0 || len > ABAC_MAX_LABEL_LEN)
		return (false);
	nul = memchr(str, '\0', len);
	return (nul == str + len - 1);
}

static bool
abac_context_arg_valid(const struct abac_context_arg *ctx)
{

	if ((ctx->vc_flags & ~ABAC_CTX_ALL) != 0 ||
	    (ctx->vc_flags & (ABAC_CTX_UID | ABAC_CTX_RUID)) ==
	    (ABAC_CTX_UID | ABAC_CTX_RUID) ||
	    ctx->vc_cap_sandboxed > 1 || ctx->vc_has_tty > 1)
		return (false);
	if ((ctx->vc_flags & ABAC_CTX_JAIL) != 0 &&
	    ctx->vc_jail_check < -1)
		return (false);
	return (true);
}

/*
 * Internal: create and populate a rule structure from syscall argument.
 *
 * This is the common implementation used by both abac_rule_add_from_arg()
 * and abac_rule_add_locked(). It handles all parsing and allocation but
 * does NOT acquire locks or insert into the rule table.
 *
 * The data buffer contains variable-length strings:
 *   subject[vr_subject_len], object[vr_object_len]
 *
 * On success, *rulep points to the newly allocated rule (caller must free
 * on error after this function returns).
 *
 * Returns:
 *   0 = success, rule allocated and populated
 *   ENOMEM = allocation failed
 *   EINVAL = invalid arguments
 */
static int
abac_rule_create(struct abac_rule_arg *arg, const char *data,
    struct abac_rule **rulep)
{
	struct abac_rule *newrule;
	const char *subject_str, *object_str;
	int error;

	if (arg == NULL || data == NULL || rulep == NULL)
		return (EINVAL);

	*rulep = NULL;

	/* Validate the fixed header and exact packed-string boundaries. */
	if (arg->vr_action > ABAC_ACTION_DENY || arg->vr_reserved != 0 ||
	    arg->vr_reserved2 != 0 || arg->vr_operations == 0 ||
	    (arg->vr_operations & ~ABAC_OP_ALL) != 0 ||
	    (arg->vr_subject_flags & ~ABAC_MATCH_NEGATE) != 0 ||
	    (arg->vr_object_flags & ~ABAC_MATCH_NEGATE) != 0 ||
	    !abac_context_arg_valid(&arg->vr_subj_context) ||
	    !abac_context_arg_valid(&arg->vr_obj_context) ||
	    !abac_packed_string_valid(data, arg->vr_subject_len) ||
	    !abac_packed_string_valid(data + arg->vr_subject_len,
	    arg->vr_object_len))
		return (EINVAL);

	/* Extract string pointers from data buffer */
	subject_str = data;
	object_str = data + arg->vr_subject_len;

	/* Allocate the rule */
	newrule = malloc(sizeof(*newrule), M_TEMP, M_NOWAIT | M_ZERO);
	if (newrule == NULL)
		return (ENOMEM);

	/* Fill in basic fields */
	newrule->vr_action = arg->vr_action;
	newrule->vr_set = arg->vr_set;
	newrule->vr_operations = arg->vr_operations;

	/* Parse subject pattern (uses compact rule pattern) */
	newrule->vr_subject.vrp_flags = arg->vr_subject_flags;
	if (subject_str[0] != '\0' && strcmp(subject_str, "*") != 0) {
		error = abac_rule_pattern_parse(subject_str, strlen(subject_str),
		    &newrule->vr_subject);
		if (error) {
			free(newrule, M_TEMP);
			return (error);
		}
	}

	/* Parse object pattern (uses compact rule pattern) */
	newrule->vr_object.vrp_flags = arg->vr_object_flags;
	if (object_str[0] != '\0' && strcmp(object_str, "*") != 0) {
		error = abac_rule_pattern_parse(object_str, strlen(object_str),
		    &newrule->vr_object);
		if (error) {
			free(newrule, M_TEMP);
			return (error);
		}
	}

	/* Copy subject context constraints */
	newrule->vr_subj_context.vc_flags = arg->vr_subj_context.vc_flags;
	newrule->vr_subj_context.vc_cap_sandboxed = arg->vr_subj_context.vc_cap_sandboxed;
	newrule->vr_subj_context.vc_has_tty = arg->vr_subj_context.vc_has_tty;
	newrule->vr_subj_context.vc_jail_check = arg->vr_subj_context.vc_jail_check;
	newrule->vr_subj_context.vc_uid = arg->vr_subj_context.vc_uid;
	newrule->vr_subj_context.vc_gid = arg->vr_subj_context.vc_gid;

	/* Copy object context constraints */
	newrule->vr_obj_context.vc_flags = arg->vr_obj_context.vc_flags;
	newrule->vr_obj_context.vc_cap_sandboxed = arg->vr_obj_context.vc_cap_sandboxed;
	newrule->vr_obj_context.vc_has_tty = arg->vr_obj_context.vc_has_tty;
	newrule->vr_obj_context.vc_jail_check = arg->vr_obj_context.vc_jail_check;
	newrule->vr_obj_context.vc_uid = arg->vr_obj_context.vc_uid;
	newrule->vr_obj_context.vc_gid = arg->vr_obj_context.vc_gid;

	*rulep = newrule;
	return (0);
}

/*
 * Free a rule structure.
 */
static void
abac_rule_free(struct abac_rule *rule)
{

	if (rule == NULL)
		return;
	free(rule, M_TEMP);
}

/*
 * Add a rule from syscall argument
 *
 * The data buffer contains variable-length strings:
 *   subject[vr_subject_len], object[vr_object_len]
 *
 * Returns:
 *   0 = success
 *   ENOSPC = table full
 *   ENOMEM = allocation failed
 *   EINVAL = invalid arguments
 */
int
abac_rule_add_from_arg(struct abac_rule_arg *arg, const char *data)
{
	struct abac_rule *newrule;
	int error;

	error = abac_rule_create(arg, data, &newrule);
	if (error)
		return (error);

	rw_wlock(&abac_rules_lock);

	/* Assign rule ID */
	newrule->vr_id = abac_next_rule_id++;

	/* Check if table is full */
	if (abac_rule_end >= ABAC_MAX_RULES) {
		rw_wunlock(&abac_rules_lock);
		abac_rule_free(newrule);
		return (ENOSPC);
	}

	/*
	 * Append at end: place new rule at abac_rule_end.
	 * This ensures new rules are checked after existing ones
	 * (intuitive first-match ordering).
	 */
	abac_rules[abac_rule_end] = newrule;
	abac_rule_count++;
	abac_rule_end++;
	abac_rebuild_active_sets();

	/* Return assigned ID to caller */
	arg->vr_id = newrule->vr_id;

	rw_wunlock(&abac_rules_lock);

	/* DTrace: rule added */
	SDT_PROBE3(abac, rules, rule, add,
	    newrule->vr_id, newrule->vr_action,
	    newrule->vr_operations);

	return (0);
}

/*
 * Internal: add a rule without locking (caller holds write lock)
 */
static int
abac_rule_add_locked(struct abac_rule_arg *arg, const char *data)
{
	struct abac_rule *newrule;
	int error;

	error = abac_rule_create(arg, data, &newrule);
	if (error)
		return (error);

	/* Assign rule ID */
	newrule->vr_id = abac_next_rule_id++;

	/* Check if table is full */
	if (abac_rule_end >= ABAC_MAX_RULES) {
		abac_rule_free(newrule);
		return (ENOSPC);
	}

	/*
	 * Append at end: place new rule at abac_rule_end.
	 */
	abac_rules[abac_rule_end] = newrule;
	abac_rule_count++;
	abac_rule_end++;

	/* DTrace: rule added */
	SDT_PROBE3(abac, rules, rule, add,
	    newrule->vr_id, newrule->vr_action,
	    newrule->vr_operations);

	return (0);
}

/*
 * Atomic rule load - replace all rules at once (like PF reload)
 *
 * This function saves existing rules, attempts to load new rules,
 * and rolls back on failure. The old_rules array is dynamically
 * allocated to avoid kernel stack overflow (stack is typically 4-8KB,
 * but ABAC_MAX_RULES pointers could be 8KB+ on 64-bit).
 */
int
abac_rules_load(struct abac_rule_load_arg *load_arg)
{
	struct abac_rule **old_rules;
	int old_count, old_end;
	uint32_t old_next_rule_id;
	char *kbuf;
	size_t offset;
	uint32_t i, loaded;
	int error;

	if (load_arg == NULL)
		return (EINVAL);

	if (load_arg->vrl_reserved != 0)
		return (EINVAL);
	if (load_arg->vrl_count > ABAC_MAX_RULES ||
	    load_arg->vrl_buflen > ABAC_MAX_RULE_LOAD_SIZE)
		return (E2BIG);

	if (load_arg->vrl_count == 0) {
		if (load_arg->vrl_buf != NULL || load_arg->vrl_buflen != 0)
			return (EINVAL);
		abac_rules_clear();
		load_arg->vrl_loaded = 0;
		return (0);
	}
	if (load_arg->vrl_buf == NULL || load_arg->vrl_buflen == 0)
		return (EINVAL);

	/* Copy buffer from userland */
	kbuf = malloc(load_arg->vrl_buflen, M_TEMP, M_WAITOK);
	error = copyin(load_arg->vrl_buf, kbuf, load_arg->vrl_buflen);
	if (error) {
		free(kbuf, M_TEMP);
		return (error);
	}

	/*
	 * Allocate rollback array dynamically to avoid stack overflow.
	 * We only need to save up to abac_rule_end entries, but allocate
	 * for ABAC_MAX_RULES to simplify indexing during restore.
	 */
	old_rules = malloc(sizeof(struct abac_rule *) * ABAC_MAX_RULES,
	    M_TEMP, M_WAITOK | M_ZERO);

	rw_wlock(&abac_rules_lock);

	/* Save old rules for rollback */
	old_count = abac_rule_count;
	old_end = abac_rule_end;
	old_next_rule_id = abac_next_rule_id;
	for (i = 0; i < ABAC_MAX_RULES; i++) {
		old_rules[i] = abac_rules[i];
		abac_rules[i] = NULL;
	}
	abac_rule_count = 0;
	abac_rule_end = 0;

	/* Parse and add new rules */
	offset = 0;
	loaded = 0;
	error = 0;

	for (i = 0; i < load_arg->vrl_count && offset < load_arg->vrl_buflen; i++) {
		struct abac_rule_arg arg;
		const char *data;
		size_t rule_size;

		if (offset + sizeof(struct abac_rule_arg) > load_arg->vrl_buflen) {
			error = EINVAL;
			break;
		}

		/* Packed records need not preserve native structure alignment. */
		memcpy(&arg, kbuf + offset, sizeof(arg));
		data = kbuf + offset + sizeof(struct abac_rule_arg);

		/*
		 * Validate length fields before calculating rule_size to
		 * prevent integer overflow. Each length must be reasonable.
		 */
		if (arg.vr_subject_len > ABAC_MAX_LABEL_LEN ||
		    arg.vr_object_len > ABAC_MAX_LABEL_LEN) {
			error = EINVAL;
			break;
		}

		rule_size = sizeof(struct abac_rule_arg) +
		    arg.vr_subject_len + arg.vr_object_len;

		if (offset + rule_size > load_arg->vrl_buflen) {
			error = EINVAL;
			break;
		}

		error = abac_rule_add_locked(&arg, data);
		if (error)
			break;

		loaded++;
		offset += rule_size;
	}
	if (error == 0 && (loaded != load_arg->vrl_count ||
	    offset != load_arg->vrl_buflen))
		error = EINVAL;

	if (error) {
		/* Rollback: restore old rules, free new rules */
		for (i = 0; i < ABAC_MAX_RULES; i++) {
			abac_rule_free(abac_rules[i]);
			abac_rules[i] = old_rules[i];
		}
		abac_rule_count = old_count;
		abac_rule_end = old_end;
		abac_next_rule_id = old_next_rule_id;
		abac_rebuild_active_sets();
	} else {
		/* Success: free old rules */
		for (i = 0; i < ABAC_MAX_RULES; i++)
			abac_rule_free(old_rules[i]);
		abac_rebuild_active_sets();
	}

	rw_wunlock(&abac_rules_lock);

	free(old_rules, M_TEMP);
	free(kbuf, M_TEMP);

	load_arg->vrl_loaded = loaded;
	return (error);
}

/*
 * Calculate the size needed to serialize a rule
 *
 * Uses dynamic allocation to avoid 8KB+ stack buffers for pattern strings.
 */
static size_t
abac_pattern_out_size(const struct abac_rule_pattern *pattern)
{
	size_t size;
	uint32_t i;

	if (pattern->vrp_npairs == 0)
		return (2); /* "*" plus NUL */
	size = 1; /* NUL */
	for (i = 0; i < pattern->vrp_npairs; i++) {
		if (i != 0)
			size++;
		size += strlen(pattern->vrp_pairs[i].vrp_key) + 1 +
		    strlen(pattern->vrp_pairs[i].vrp_value);
	}
	return (size);
}

static size_t
abac_rule_out_size(const struct abac_rule *rule)
{

	return (sizeof(struct abac_rule_out) +
	    abac_pattern_out_size(&rule->vr_subject) +
	    abac_pattern_out_size(&rule->vr_object));
}

/*
 * Serialize a rule to buffer
 *
 * Uses dynamic allocation to avoid 8KB+ stack buffers for pattern strings.
 */
static size_t
abac_rule_serialize(const struct abac_rule *rule, char *buf, size_t buflen,
    char *subj_buf, char *obj_buf)
{
	struct abac_rule_out out;
	char *data;
	size_t subj_len, obj_len, total;

	subj_len = abac_rule_pattern_to_string(&rule->vr_subject, subj_buf,
	    ABAC_MAX_LABEL_LEN) + 1;
	obj_len = abac_rule_pattern_to_string(&rule->vr_object, obj_buf,
	    ABAC_MAX_LABEL_LEN) + 1;

	total = sizeof(struct abac_rule_out) + subj_len + obj_len;
	if (total > buflen)
		return (0);

	/* Fill header */
	memset(&out, 0, sizeof(out));
	out.vr_id = rule->vr_id;
	out.vr_action = rule->vr_action;
	out.vr_set = rule->vr_set;
	out.vr_operations = rule->vr_operations;
	out.vr_subject_flags = rule->vr_subject.vrp_flags;
	out.vr_object_flags = rule->vr_object.vrp_flags;
	out.vr_subj_context.vc_flags = rule->vr_subj_context.vc_flags;
	out.vr_subj_context.vc_cap_sandboxed = rule->vr_subj_context.vc_cap_sandboxed;
	out.vr_subj_context.vc_has_tty = rule->vr_subj_context.vc_has_tty;
	out.vr_subj_context.vc_jail_check = rule->vr_subj_context.vc_jail_check;
	out.vr_subj_context.vc_uid = rule->vr_subj_context.vc_uid;
	out.vr_subj_context.vc_gid = rule->vr_subj_context.vc_gid;
	out.vr_obj_context.vc_flags = rule->vr_obj_context.vc_flags;
	out.vr_obj_context.vc_cap_sandboxed = rule->vr_obj_context.vc_cap_sandboxed;
	out.vr_obj_context.vc_has_tty = rule->vr_obj_context.vc_has_tty;
	out.vr_obj_context.vc_jail_check = rule->vr_obj_context.vc_jail_check;
	out.vr_obj_context.vc_uid = rule->vr_obj_context.vc_uid;
	out.vr_obj_context.vc_gid = rule->vr_obj_context.vc_gid;
	out.vr_subject_len = subj_len;
	out.vr_object_len = obj_len;

	/* Copy strings */
	data = buf + sizeof(struct abac_rule_out);
	memcpy(buf, &out, sizeof(out));
	memcpy(data, subj_buf, subj_len);
	data += subj_len;
	memcpy(data, obj_buf, obj_len);

	return (total);
}

/*
 * List rules to userland buffer
 */
int
abac_rules_list(struct abac_rule_list_arg *list_arg)
{
	const struct abac_rule *rule;
	uint32_t copied = 0;
	uint32_t offset;
	size_t buf_used = 0;
	char *kbuf = NULL, *subj_buf = NULL, *obj_buf = NULL;
	int i, slot, error = 0;

	if (list_arg == NULL)
		return (EINVAL);

	offset = list_arg->vrl_offset;

	if (list_arg->vrl_buf != NULL && list_arg->vrl_buflen > 0) {
		kbuf = malloc(list_arg->vrl_buflen, M_TEMP, M_WAITOK);
		subj_buf = malloc(ABAC_MAX_LABEL_LEN, M_TEMP, M_WAITOK);
		obj_buf = malloc(ABAC_MAX_LABEL_LEN, M_TEMP, M_WAITOK);
	}

	rw_rlock(&abac_rules_lock);

	list_arg->vrl_total = abac_rule_count;

	/* Skip to offset */
	slot = 0;
	for (i = 0; i < abac_rule_end && slot < (int)offset; i++) {
		if (abac_rules[i] != NULL)
			slot++;
	}

	/* Serialize rules */
	for (; i < abac_rule_end; i++) {
		rule = abac_rules[i];
		if (rule == NULL)
			continue;

		if (kbuf != NULL) {
			size_t needed = abac_rule_out_size(rule);
			if (buf_used + needed > list_arg->vrl_buflen)
				break;

			size_t written = abac_rule_serialize(rule,
			    kbuf + buf_used, list_arg->vrl_buflen - buf_used,
			    subj_buf, obj_buf);
			if (written == 0)
				break;
			buf_used += written;
		}
		copied++;
	}

	list_arg->vrl_count = copied;

	rw_runlock(&abac_rules_lock);

	if (kbuf != NULL && buf_used > 0) {
		error = copyout(kbuf, list_arg->vrl_buf, buf_used);
	}

	if (kbuf != NULL)
		free(kbuf, M_TEMP);
	if (subj_buf != NULL)
		free(subj_buf, M_TEMP);
	if (obj_buf != NULL)
		free(obj_buf, M_TEMP);

	return (error);
}

/*
 * Test if an access would be allowed without actually performing it
 */
int
abac_rules_test_access(const char *subject, size_t subject_len,
    const char *object, size_t object_len, uint32_t operation,
    uint32_t *result, uint32_t *rule_id)
{
	struct abac_label *subj_label, *obj_label;
	char *converted;
	const struct abac_rule *rule;
	int i, si, error;
	uint16_t set;

	if (result == NULL || subject_len > UINT16_MAX ||
	    object_len > UINT16_MAX ||
	    !abac_packed_string_valid(subject, (uint16_t)subject_len) ||
	    !abac_packed_string_valid(object, (uint16_t)object_len) ||
	    operation == 0 || (operation & ~ABAC_OP_ALL) != 0 ||
	    (operation & (operation - 1)) != 0)
		return (EINVAL);

	/* Allocate labels dynamically - too large for stack */
	subj_label = malloc(sizeof(*subj_label), M_TEMP, M_WAITOK | M_ZERO);
	obj_label = malloc(sizeof(*obj_label), M_TEMP, M_WAITOK | M_ZERO);
	converted = malloc(ABAC_MAX_LABEL_LEN, M_TEMP, M_WAITOK);

	error = 0;

	/* Parse labels */
	if (subject != NULL && subject_len > 0 && subject[0] != '\0') {
		error = abac_convert_label_format(subject, converted,
		    ABAC_MAX_LABEL_LEN);
		if (error == 0)
			error = abac_label_parse(converted, strlen(converted),
			    subj_label);
		if (error != 0)
			goto out_free;
	}

	if (object != NULL && object_len > 0 && object[0] != '\0') {
		error = abac_convert_label_format(object, converted,
		    ABAC_MAX_LABEL_LEN);
		if (error == 0)
			error = abac_label_parse(converted, strlen(converted),
			    obj_label);
		if (error != 0)
			goto out_free;
	}

	*result = EACCES;
	if (rule_id != NULL)
		*rule_id = 0;

	rw_rlock(&abac_rules_lock);

	for (si = 0; si < abac_active_set_count; si++) {
		set = abac_active_sets[si];
		if (!ABAC_SET_IS_ENABLED(set))
			continue;
		for (i = 0; i < abac_rule_end; i++) {
			rule = abac_rules[i];
			if (rule == NULL || rule->vr_set != set ||
			    (rule->vr_operations & operation) == 0)
				continue;

			/* The dry-run ABI has no process context to evaluate. */
			if (rule->vr_subj_context.vc_flags != 0 ||
			    rule->vr_obj_context.vc_flags != 0)
				continue;
			if (!abac_rule_pattern_match(subj_label, &rule->vr_subject) ||
			    !abac_rule_pattern_match(obj_label, &rule->vr_object))
				continue;

			if (rule_id != NULL)
				*rule_id = rule->vr_id;
			if (rule->vr_action == ABAC_ACTION_ALLOW)
				*result = 0;
			else
				*result = EACCES;
			goto out;
		}
	}

	/* No rule matched - use default policy */
	*result = abac_default_policy ? EACCES : 0;

out:
	rw_runlock(&abac_rules_lock);

out_free:
	free(converted, M_TEMP);
	free(obj_label, M_TEMP);
	free(subj_label, M_TEMP);

	return (error);
}
