/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 *
 * ABAC Pattern and Context Matching
 *
 * Handles pattern matching for rules and context constraint evaluation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * Check if a label matches a compact rule pattern
 *
 * This function matches a label against the compact abac_rule_pattern
 * structure used in rules. It has the same semantics as abac_label_match
 * but operates on the smaller rule pattern structure.
 *
 * Pattern matching rules:
 * - Empty pattern (npairs=0) = wildcard (matches anything)
 * - Each pattern pair must exist in the label
 * - Pattern value "*" matches any value for that key
 * - ABAC_MATCH_NEGATE inverts the result
 */
bool
abac_rule_pattern_match(const struct abac_label *label,
    const struct abac_rule_pattern *pattern)
{
	const char *label_value;
	uint32_t i;
	bool match = true;

	if (label == NULL || pattern == NULL)
		return (false);

	/* Empty pattern matches everything */
	if (pattern->vrp_npairs == 0) {
		match = true;
		goto done;
	}

	/* Check each pattern pair against the label */
	for (i = 0; i < pattern->vrp_npairs && match; i++) {
		const struct abac_rule_pair *rp = &pattern->vrp_pairs[i];

		/* Find this key in the label */
		label_value = abac_label_get_value(label, rp->vrp_key);

		if (label_value == NULL) {
			/* Key not found in label - no match */
			match = false;
		} else if (strcmp(rp->vrp_value, "*") != 0) {
			/* Not a wildcard - must match exactly */
			if (strcmp(label_value, rp->vrp_value) != 0)
				match = false;
		}
		/* else: wildcard "*" matches any value - continue */
	}

done:
	/* Handle negation */
	if (pattern->vrp_flags & ABAC_MATCH_NEGATE)
		match = !match;

	return (match);
}

/*
 * Context attributes
 *
 * Context constraints make a rule conditional on attributes of the subject
 * or, for process operations, of the target process:
 * - Capability mode (sandboxed or not)
 * - Jail context (host, specific jail, or any jail)
 * - User ID (effective UID), real UID, group ID (effective GID)
 * - Whether the process has a controlling terminal
 *
 * The attributes are taken once per check, before abac_rules_lock is
 * acquired, and matching compares plain values: it takes no lock.  The
 * process hooks run with the target's process lock held, and the rule lock
 * is taken under it; a process lock taken while matching would order the
 * rule lock before a process lock, and the caller's process lock after the
 * target's (two processes acting on each other).
 *
 * "Has a controlling terminal" is answered as /dev/tty answers it
 * (ctty_clone()) for a target process: P_CONTROLT, and a session that
 * still holds its terminal (s_ttyvp) and has not had it revoked, read
 * under the target's lock that the MAC caller holds.  For the calling process only P_CONTROLT is
 * read, without its lock: the hook may hold another process's lock, so
 * the caller's process group, and the session through it, cannot be
 * held stable (setsid(2) in a sibling thread can free the old session).
 * A caller whose session leader has exited or given the terminal up
 * therefore still counts as having one; mac_abac(4) documents this.
 */
static void
abac_ctx_attrs_cred(struct abac_ctx_attrs *attrs, struct ucred *cred,
    bool has_tty)
{

	attrs->va_valid = true;
	attrs->va_capmode = (cred->cr_flags & CRED_FLAG_CAPMODE) != 0;
	attrs->va_has_tty = has_tty;
	attrs->va_jailid = cred->cr_prison != NULL ? cred->cr_prison->pr_id : 0;
	attrs->va_uid = cred->cr_uid;
	attrs->va_ruid = cred->cr_ruid;
	attrs->va_gid = cred->cr_gid;
}

/* The subject: the hook's credential (NULL: no subject context). */
void
abac_ctx_attrs_subject(struct abac_ctx_attrs *attrs, struct ucred *cred)
{

	if (cred == NULL) {
		attrs->va_valid = false;
		return;
	}
	abac_ctx_attrs_cred(attrs, cred,
	    (atomic_load_int(&curproc->p_flag) & P_CONTROLT) != 0);
}

/* A target process, locked by the MAC caller (NULL: no object context). */
void
abac_ctx_attrs_object(struct abac_ctx_attrs *attrs, struct proc *p)
{
	struct session *sp;
	struct vnode *vp;
	bool has_tty;

	if (p == NULL) {
		attrs->va_valid = false;
		return;
	}
	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (p->p_ucred == NULL) {
		attrs->va_valid = false;
		return;
	}
	/*
	 * The process lock keeps p_pgrp, and with it the session, stable.
	 * The terminal is the session's while the session still holds it and
	 * it has not been revoked: s_ttyvp is cleared when the session leader
	 * exits or gives the terminal up (killjobc(), TIOCNOTTY), while the
	 * members keep P_CONTROLT, and revoke(2) leaves it pointing at a
	 * reclaimed vnode.  This is the test of /dev/tty (ctty_clone()).
	 * s_ttyvp is cleared under the session mutex before its reference is
	 * released, so the vnode can be read while the mutex is held; the
	 * session mutex orders after the process lock.
	 */
	has_tty = false;
	if ((p->p_flag & P_CONTROLT) != 0 && p->p_pgrp != NULL) {
		sp = p->p_pgrp->pg_session;
		SESS_LOCK(sp);
		vp = sp->s_ttyvp;
		has_tty = vp != NULL && vp->v_type != VBAD &&
		    vp->v_rdev != NULL;
		SESS_UNLOCK(sp);
	}
	abac_ctx_attrs_cred(attrs, p->p_ucred, has_tty);
}

/*
 * Check if context constraints match the given attributes.  A constraint
 * without known attributes does not match.
 */
bool
abac_context_matches(const struct abac_context *ctx,
    const struct abac_ctx_attrs *attrs)
{

	/* If no context flags set, match everything */
	if (ctx->vc_flags == 0)
		return (true);
	if (attrs == NULL || !attrs->va_valid)
		return (false);

	if ((ctx->vc_flags & ABAC_CTX_CAP_SANDBOXED) != 0 &&
	    attrs->va_capmode != ctx->vc_cap_sandboxed)
		return (false);

	if ((ctx->vc_flags & ABAC_CTX_JAIL) != 0) {
		switch (ctx->vc_jail_check) {
		case 0:
			/* Must be on host (jail 0) */
			if (attrs->va_jailid != 0)
				return (false);
			break;
		case -1:
			/* Must be in any jail (not host) */
			if (attrs->va_jailid == 0)
				return (false);
			break;
		default:
			/* Must be in specific jail */
			if (attrs->va_jailid != ctx->vc_jail_check)
				return (false);
			break;
		}
	}

	if ((ctx->vc_flags & ABAC_CTX_UID) != 0 &&
	    attrs->va_uid != ctx->vc_uid)
		return (false);
	if ((ctx->vc_flags & ABAC_CTX_GID) != 0 &&
	    attrs->va_gid != ctx->vc_gid)
		return (false);
	if ((ctx->vc_flags & ABAC_CTX_RUID) != 0 &&
	    attrs->va_ruid != ctx->vc_uid)
		return (false);
	if ((ctx->vc_flags & ABAC_CTX_HAS_TTY) != 0 &&
	    attrs->va_has_tty != ctx->vc_has_tty)
		return (false);

	return (true);
}

/*
 * Check if a rule matches the current access request
 *
 * subj_attrs: the subject's context attributes
 * obj_attrs: the target process's, for process operations (may be NULL)
 *
 * Uses abac_rule_pattern_match for the compact rule pattern structures.
 */
bool
abac_rule_matches(const struct abac_rule *rule,
    const struct abac_label *subj,
    const struct abac_label *obj,
    uint32_t op,
    const struct abac_ctx_attrs *subj_attrs,
    const struct abac_ctx_attrs *obj_attrs)
{

	/* Check if operation is covered by this rule */
	if ((rule->vr_operations & op) == 0)
		return (false);

	/* Check subject pattern (uses compact rule pattern) */
	if (!abac_rule_pattern_match(subj, &rule->vr_subject))
		return (false);

	/* Check object pattern (uses compact rule pattern) */
	if (!abac_rule_pattern_match(obj, &rule->vr_object))
		return (false);

	/* Check subject context constraints (jail, capability mode, etc.) */
	if (!abac_context_matches(&rule->vr_subj_context, subj_attrs))
		return (false);

	/* Check object context constraints (for proc operations) */
	if (!abac_context_matches(&rule->vr_obj_context, obj_attrs))
		return (false);

	return (true);
}

/*
 * Serialize a compact rule pattern to a string
 *
 * Converts the parsed key=value pairs back to a comma-separated string.
 * Returns the number of characters written (not including null terminator).
 */
size_t
abac_rule_pattern_to_string(const struct abac_rule_pattern *pattern,
    char *buf, size_t buflen)
{
	size_t pos = 0;
	uint32_t i;

	if (buf == NULL || buflen == 0)
		return (0);

	buf[0] = '\0';

	/* Empty pattern = wildcard */
	if (pattern->vrp_npairs == 0) {
		if (buflen > 1) {
			buf[0] = '*';
			buf[1] = '\0';
			return (1);
		}
		return (0);
	}

	/* Build comma-separated key=value string */
	for (i = 0; i < pattern->vrp_npairs && pos < buflen - 1; i++) {
		const struct abac_rule_pair *pair = &pattern->vrp_pairs[i];
		size_t needed, copied;

		if (i > 0 && pos < buflen - 1)
			buf[pos++] = ',';

		/* Calculate space needed for "key=value" */
		needed = strlen(pair->vrp_key) + 1 + strlen(pair->vrp_value);
		if (pos + needed >= buflen)
			break;

		copied = strlcpy(buf + pos, pair->vrp_key, buflen - pos);
		pos = (pos + copied >= buflen) ? buflen - 1 : pos + copied;
		if (pos < buflen - 1)
			buf[pos++] = '=';
		copied = strlcpy(buf + pos, pair->vrp_value, buflen - pos);
		pos = (pos + copied >= buflen) ? buflen - 1 : pos + copied;
	}

	return (pos);
}

/*
 * Convert comma-separated label string to newline-separated format
 *
 * CLI users provide labels like "type=user,domain=web" but abac_label_parse
 * expects newline-separated format like "type=user\ndomain=web\n".
 */
int
abac_convert_label_format(const char *src, char *dst, size_t dstlen)
{
	size_t i, j;

	if (src == NULL || dst == NULL || dstlen == 0)
		return (EINVAL);
	for (i = 0, j = 0; src[i] != '\0' && j < dstlen - 1; i++) {
		if (src[i] == ',')
			dst[j++] = '\n';
		else
			dst[j++] = src[i];
	}
	if (src[i] != '\0') {
		dst[0] = '\0';
		return (E2BIG);
	}
	/* Ensure trailing newline for proper parsing */
	if (j > 0 && dst[j - 1] != '\n') {
		if (j >= dstlen - 1) {
			dst[0] = '\0';
			return (E2BIG);
		}
		dst[j++] = '\n';
	}
	dst[j] = '\0';
	return (0);
}
