/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC Rule Engine
 *
 * Manages the rule table and evaluates access decisions.
 * Pattern matching is in abac_match.c.
 * Syscall handlers are in abac_syscall.c.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>

#include <machine/atomic.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"
#include "abac_dtrace.h"

/*
 * Rule table storage
 *
 * abac_rule_count: number of non-NULL rules (for stats/limits)
 * abac_rule_end: index after last rule (for iteration bounds)
 *
 * Rules are appended at abac_rule_end. Removals leave holes (NULL).
 * Iteration must scan 0..abac_rule_end-1, skipping NULLs.
 */
struct abac_rule *abac_rules[ABAC_MAX_RULES];
int abac_rule_count;
int abac_rule_end;
struct rwlock abac_rules_lock;

/*
 * Rule set management
 *
 * abac_set_enabled: Bitmap tracking which sets are enabled (8KB for 65536 sets)
 * abac_active_sets: Sorted list of sets that have rules (for efficient iteration)
 * abac_active_set_count: Number of entries in active_sets
 *
 * Evaluation iterates through active_sets in order (set 0 first, then 1, etc.)
 * and skips disabled sets. This provides IPFW-style set semantics with PF-style
 * ordered evaluation.
 */
uint8_t abac_set_enabled[ABAC_SET_BITMAP_SIZE];
uint16_t abac_active_sets[ABAC_MAX_RULES];	/* Max distinct sets = max rules */
uint16_t abac_active_set_count;

/*
 * Statistics - accessed atomically via atomic_add_64()
 */
uint64_t abac_checks;
uint64_t abac_allowed;
uint64_t abac_denied;

/*
 * Label statistics - defined in mac_abac.c
 */
extern uint64_t abac_labels_read;
extern uint64_t abac_labels_default;

/*
 * Next rule ID counter
 */
uint32_t abac_next_rule_id = 1;

SYSCTL_DECL(_security_mac_mac_abac);

SYSCTL_UQUAD(_security_mac_mac_abac, OID_AUTO, checks, CTLFLAG_RD,
    &abac_checks, 0, "Total access checks");

SYSCTL_UQUAD(_security_mac_mac_abac, OID_AUTO, allowed, CTLFLAG_RD,
    &abac_allowed, 0, "Allowed accesses");

SYSCTL_UQUAD(_security_mac_mac_abac, OID_AUTO, denied, CTLFLAG_RD,
    &abac_denied, 0, "Denied accesses");

SYSCTL_INT(_security_mac_mac_abac, OID_AUTO, rule_count, CTLFLAG_RD,
    &abac_rule_count, 0, "Number of active rules");

/*
 * Default policy when no rule matches
 * 0 = allow (permissive default)
 * 1 = deny (secure default)
 */
int abac_default_policy = 0;

SYSCTL_INT(_security_mac_mac_abac, OID_AUTO, default_policy, CTLFLAG_RW,
    &abac_default_policy, 0,
    "Default policy when no rule matches (0=allow, 1=deny)");

/*
 * Initialize rule subsystem
 */
void
abac_rules_init(void)
{

	rw_init(&abac_rules_lock, "abac rules");
	memset(abac_rules, 0, sizeof(abac_rules));
	abac_rule_count = 0;
	abac_rule_end = 0;

	/* Initialize set management - all sets enabled by default */
	memset(abac_set_enabled, 0xFF, sizeof(abac_set_enabled));
	abac_active_set_count = 0;

	abac_checks = 0;
	abac_allowed = 0;
	abac_denied = 0;

}

/*
 * Destroy rule subsystem
 */
void
abac_rules_destroy(void)
{
	struct abac_rule *rule;
	int i;

	/* Free all dynamically allocated rules */
	rw_wlock(&abac_rules_lock);
	for (i = 0; i < ABAC_MAX_RULES; i++) {
		rule = abac_rules[i];
		if (rule != NULL) {
			abac_rules[i] = NULL;
			if (rule->vr_newlabel != NULL)
				free(rule->vr_newlabel, M_TEMP);
			free(rule, M_TEMP);
		}
	}
	abac_rule_count = 0;
	rw_wunlock(&abac_rules_lock);

	rw_destroy(&abac_rules_lock);
}

/*
 * Evaluate rules against an access request
 *
 * Returns:
 *   0 = allowed
 *   EACCES = denied
 *
 * Uses first-match semantics with set-ordered evaluation.
 * Sets are evaluated in ascending order (set 0 first, then 1, etc.).
 * Within each set, rules are evaluated in the order they were added.
 * Disabled sets are skipped entirely.
 * If no rule matches, uses default policy.
 *
 * obj_proc is optional - only needed for proc operations (debug/signal/sched)
 * to enable object context checking. Pass NULL for vnode operations.
 */
int
abac_rules_check(struct ucred *cred, struct abac_label *subj,
    struct abac_label *obj, uint32_t op, struct proc *obj_proc)
{
	const struct abac_rule *rule;
	int i, si, result;
	uint16_t set;
	uint32_t matched_rule_id = 0;

	atomic_add_64(&abac_checks, 1);

	/* Safety checks */
	if (subj == NULL || obj == NULL) {
		atomic_add_64(&abac_allowed, 1);
		return (0);
	}

	/* DTrace: check entry (pass hash for efficiency) */
	SDT_PROBE3(abac, rules, check, entry, subj->vl_hash, obj->vl_hash, op);

	rw_rlock(&abac_rules_lock);

	result = EACCES;	/* Default deny */

	/* Iterate sets in ascending order */
	for (si = 0; si < abac_active_set_count; si++) {
		set = abac_active_sets[si];

		/* Skip disabled sets */
		if (!ABAC_SET_IS_ENABLED(set))
			continue;

		/* Evaluate rules in this set */
		for (i = 0; i < abac_rule_end; i++) {
			rule = abac_rules[i];
			if (rule == NULL)
				continue;

			/* Only consider rules in the current set */
			if (rule->vr_set != set)
				continue;

			if (abac_rule_matches(rule, subj, obj, op, cred, obj_proc)) {
				/* DTrace: rule matched */
				SDT_PROBE3(abac, rules, rule, match,
				    rule->vr_id, rule->vr_action, op);
				matched_rule_id = rule->vr_id;

				if (rule->vr_action == ABAC_ACTION_ALLOW ||
				    rule->vr_action == ABAC_ACTION_TRANSITION)
					result = 0;
				else
					result = EACCES;
				goto out;
			}
		}
	}

	/*
	 * No rule matched - use default policy.
	 */
	SDT_PROBE2(abac, rules, rule, nomatch, abac_default_policy, op);

	if (abac_default_policy == 0)
		result = 0;
	else
		result = EACCES;

out:
	rw_runlock(&abac_rules_lock);

	/* DTrace: check-allow or check-deny (pass hash for efficiency) */
	if (result == 0) {
		SDT_PROBE4(abac, rules, check, allow,
		    subj->vl_hash, obj->vl_hash, op, matched_rule_id);
		atomic_add_64(&abac_allowed, 1);
	} else {
		SDT_PROBE4(abac, rules, check, deny,
		    subj->vl_hash, obj->vl_hash, op, matched_rule_id);
		atomic_add_64(&abac_denied, 1);
	}

	/* DTrace: check return */
	SDT_PROBE2(abac, rules, check, return, result, op);

	(void)matched_rule_id;	/* Silence warning when DTrace compiled out */

	return (result);
}

/*
 * Check if exec will cause a label transition
 *
 * Returns true if a TRANSITION rule matches, false otherwise.
 * Uses set-ordered evaluation (set 0 first, then 1, etc.).
 */
bool
abac_rules_will_transition(struct ucred *cred, struct abac_label *subj,
    struct abac_label *obj)
{
	const struct abac_rule *rule;
	bool result = false;
	int i, si;
	uint16_t set;

	if (subj == NULL || obj == NULL)
		return (false);

	rw_rlock(&abac_rules_lock);

	/* Iterate sets in ascending order */
	for (si = 0; si < abac_active_set_count; si++) {
		set = abac_active_sets[si];

		/* Skip disabled sets */
		if (!ABAC_SET_IS_ENABLED(set))
			continue;

		for (i = 0; i < abac_rule_end; i++) {
			rule = abac_rules[i];
			if (rule == NULL)
				continue;

			/* Only consider rules in the current set */
			if (rule->vr_set != set)
				continue;

			/* Only check EXEC operations for transitions */
			if ((rule->vr_operations & ABAC_OP_EXEC) == 0)
				continue;

			if (rule->vr_action != ABAC_ACTION_TRANSITION)
				continue;

			/* Transitions don't need object context (no target process) */
			if (abac_rule_matches(rule, subj, obj, ABAC_OP_EXEC, cred, NULL)) {
				result = true;
				goto out;
			}
		}
	}

out:
	rw_runlock(&abac_rules_lock);
	return (result);
}

/*
 * Get the new label for a transition
 *
 * Returns 0 and copies the new label if a TRANSITION rule matches,
 * returns ENOENT if no transition rule matches.
 * Uses set-ordered evaluation (set 0 first, then 1, etc.).
 */
int
abac_rules_get_transition(struct ucred *cred, struct abac_label *subj,
    struct abac_label *obj, struct abac_label *newlabel)
{
	const struct abac_rule *rule;
	int i, si, result = ENOENT;
	uint16_t set;

	if (subj == NULL || obj == NULL || newlabel == NULL)
		return (EINVAL);

	rw_rlock(&abac_rules_lock);

	/* Iterate sets in ascending order */
	for (si = 0; si < abac_active_set_count; si++) {
		set = abac_active_sets[si];

		/* Skip disabled sets */
		if (!ABAC_SET_IS_ENABLED(set))
			continue;

		for (i = 0; i < abac_rule_end; i++) {
			rule = abac_rules[i];
			if (rule == NULL)
				continue;

			/* Only consider rules in the current set */
			if (rule->vr_set != set)
				continue;

			/* Only check EXEC operations for transitions */
			if ((rule->vr_operations & ABAC_OP_EXEC) == 0)
				continue;

			if (rule->vr_action != ABAC_ACTION_TRANSITION)
				continue;

			/* Transitions don't need object context (no target process) */
			if (abac_rule_matches(rule, subj, obj, ABAC_OP_EXEC, cred, NULL)) {
				if (rule->vr_newlabel != NULL) {
					abac_label_copy(rule->vr_newlabel, newlabel);
					result = 0;
				}
				goto out;
			}
		}
	}

out:
	rw_runlock(&abac_rules_lock);
	return (result);
}

/*
 * Remove a rule by ID
 *
 * Returns:
 *   0 = success
 *   ENOENT = rule not found
 */
int
abac_rule_remove(uint32_t id)
{
	struct abac_rule *rule;
	int i;

	rw_wlock(&abac_rules_lock);

	for (i = 0; i < ABAC_MAX_RULES; i++) {
		rule = abac_rules[i];
		if (rule != NULL && rule->vr_id == id) {
			abac_rules[i] = NULL;
			abac_rule_count--;
			rw_wunlock(&abac_rules_lock);
			/* DTrace: rule removed */
			SDT_PROBE1(abac, rules, rule, remove, id);
			if (rule->vr_newlabel != NULL)
				free(rule->vr_newlabel, M_TEMP);
			free(rule, M_TEMP);
			return (0);
		}
	}

	rw_wunlock(&abac_rules_lock);
	return (ENOENT);
}

/*
 * Clear all rules
 */
void
abac_rules_clear(void)
{
	struct abac_rule *rule;
	int i;
	uint32_t cleared = 0;

	rw_wlock(&abac_rules_lock);

	for (i = 0; i < ABAC_MAX_RULES; i++) {
		rule = abac_rules[i];
		if (rule != NULL) {
			abac_rules[i] = NULL;
			if (rule->vr_newlabel != NULL)
				free(rule->vr_newlabel, M_TEMP);
			free(rule, M_TEMP);
			cleared++;
		}
	}

	abac_rule_count = 0;
	abac_rule_end = 0;
	abac_active_set_count = 0;	/* Reset active sets */

	rw_wunlock(&abac_rules_lock);

	/* DTrace: rules cleared */
	SDT_PROBE1(abac, rules, rule, clear, cleared);

	(void)cleared;

}

/*
 * Get statistics (via mac_syscall)
 */
void
abac_rules_get_stats(struct abac_stats *stats)
{

	rw_rlock(&abac_rules_lock);
	stats->vs_checks = abac_checks;
	stats->vs_allowed = abac_allowed;
	stats->vs_denied = abac_denied;
	stats->vs_labels_read = abac_labels_read;
	stats->vs_labels_default = abac_labels_default;
	stats->vs_rule_count = abac_rule_count;
	rw_runlock(&abac_rules_lock);
}

/*
 * ============================================================
 * Set Management Functions
 * ============================================================
 */

/*
 * Rebuild the active_sets array by scanning all rules
 * Must be called with abac_rules_lock held for writing
 */
void
abac_rebuild_active_sets(void)
{
	const struct abac_rule *rule;
	uint16_t sets_seen[ABAC_MAX_RULES];
	int nsets = 0;
	int i, j, k;
	uint16_t temp;
	bool found;

	/* Collect all unique sets */
	for (i = 0; i < abac_rule_end; i++) {
		rule = abac_rules[i];
		if (rule == NULL)
			continue;

		/* Check if we've seen this set */
		found = false;
		for (j = 0; j < nsets; j++) {
			if (sets_seen[j] == rule->vr_set) {
				found = true;
				break;
			}
		}

		if (!found && nsets < ABAC_MAX_RULES)
			sets_seen[nsets++] = rule->vr_set;
	}

	/* Sort sets in ascending order (simple insertion sort) */
	for (i = 1; i < nsets; i++) {
		temp = sets_seen[i];
		k = i - 1;
		while (k >= 0 && sets_seen[k] > temp) {
			sets_seen[k + 1] = sets_seen[k];
			k--;
		}
		sets_seen[k + 1] = temp;
	}

	/* Copy to active_sets */
	for (i = 0; i < nsets; i++)
		abac_active_sets[i] = sets_seen[i];
	abac_active_set_count = nsets;
}

/*
 * Enable a range of sets
 */
void
abac_set_enable_range(uint16_t start, uint16_t end)
{
	uint16_t s;

	rw_wlock(&abac_rules_lock);
	for (s = start; s <= end; s++)
		ABAC_SET_ENABLE(s);
	rw_wunlock(&abac_rules_lock);
}

/*
 * Disable a range of sets
 */
void
abac_set_disable_range(uint16_t start, uint16_t end)
{
	uint16_t s;

	rw_wlock(&abac_rules_lock);
	for (s = start; s <= end; s++)
		ABAC_SET_DISABLE(s);
	rw_wunlock(&abac_rules_lock);
}

/*
 * Swap two sets atomically
 * All rules in set_a become set_b and vice versa
 */
int
abac_set_swap(uint16_t set_a, uint16_t set_b)
{
	struct abac_rule *rule;
	int i;
	bool enabled_a, enabled_b;

	if (set_a == set_b)
		return (0);

	rw_wlock(&abac_rules_lock);

	/* Swap set numbers on all affected rules */
	for (i = 0; i < abac_rule_end; i++) {
		rule = abac_rules[i];
		if (rule == NULL)
			continue;

		if (rule->vr_set == set_a)
			rule->vr_set = set_b;
		else if (rule->vr_set == set_b)
			rule->vr_set = set_a;
	}

	/* Swap enabled state */
	enabled_a = ABAC_SET_IS_ENABLED(set_a);
	enabled_b = ABAC_SET_IS_ENABLED(set_b);

	if (enabled_a)
		ABAC_SET_ENABLE(set_b);
	else
		ABAC_SET_DISABLE(set_b);

	if (enabled_b)
		ABAC_SET_ENABLE(set_a);
	else
		ABAC_SET_DISABLE(set_a);

	/* Rebuild active sets (set numbers changed but list is still valid) */
	abac_rebuild_active_sets();

	rw_wunlock(&abac_rules_lock);
	return (0);
}

/*
 * Move all rules from one set to another
 */
int
abac_set_move(uint16_t from_set, uint16_t to_set)
{
	struct abac_rule *rule;
	int i;

	if (from_set == to_set)
		return (0);

	rw_wlock(&abac_rules_lock);

	for (i = 0; i < abac_rule_end; i++) {
		rule = abac_rules[i];
		if (rule == NULL)
			continue;

		if (rule->vr_set == from_set)
			rule->vr_set = to_set;
	}

	abac_rebuild_active_sets();

	rw_wunlock(&abac_rules_lock);
	return (0);
}

/*
 * Clear all rules in a specific set
 */
void
abac_set_clear(uint16_t set)
{
	struct abac_rule *rule;
	int i;
	uint32_t cleared = 0;

	rw_wlock(&abac_rules_lock);

	for (i = 0; i < abac_rule_end; i++) {
		rule = abac_rules[i];
		if (rule == NULL)
			continue;

		if (rule->vr_set == set) {
			abac_rules[i] = NULL;
			abac_rule_count--;
			if (rule->vr_newlabel != NULL)
				free(rule->vr_newlabel, M_TEMP);
			free(rule, M_TEMP);
			cleared++;
		}
	}

	abac_rebuild_active_sets();

	rw_wunlock(&abac_rules_lock);

	(void)cleared;
}

/*
 * Get information about sets
 * Caller provides range to query, we fill in rule counts and enabled status
 */
void
abac_set_get_info(struct abac_set_list_arg *arg)
{
	const struct abac_rule *rule;
	uint32_t calc_end;
	uint16_t s, end_set;
	int i, idx;

	if (arg->vsl_count == 0 || arg->vsl_count > 256)
		arg->vsl_count = 256;

	/* Calculate end_set avoiding uint16_t overflow */
	calc_end = (uint32_t)arg->vsl_start + arg->vsl_count - 1;
	if (calc_end >= ABAC_MAX_SETS)
		end_set = ABAC_MAX_SETS - 1;
	else
		end_set = (uint16_t)calc_end;

	/* Zero out results */
	memset(arg->vsl_rule_counts, 0, sizeof(arg->vsl_rule_counts));
	memset(arg->vsl_enabled, 0, sizeof(arg->vsl_enabled));

	rw_rlock(&abac_rules_lock);

	/* Count rules per set */
	for (i = 0; i < abac_rule_end; i++) {
		rule = abac_rules[i];
		if (rule == NULL)
			continue;

		s = rule->vr_set;
		if (s >= arg->vsl_start && s <= end_set) {
			idx = s - arg->vsl_start;
			if (idx < 256)
				arg->vsl_rule_counts[idx]++;
		}
	}

	/* Copy enabled bits for the queried range */
	for (s = arg->vsl_start; s <= end_set; s++) {
		idx = s - arg->vsl_start;
		if (idx < 256 && ABAC_SET_IS_ENABLED(s))
			arg->vsl_enabled[idx / 8] |= (1 << (idx % 8));
	}

	rw_runlock(&abac_rules_lock);
}
