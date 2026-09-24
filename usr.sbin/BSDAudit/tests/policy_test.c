/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <bsm/audit_kevents.h>
#include <atf-c.h>
#include <stddef.h>

#include "auditcmp_policy.h"

ATF_TC_WITHOUT_HEAD(identity_map);
ATF_TC_BODY(identity_map, tc)
{

	ATF_CHECK_EQ(AUE_NETWORKCMP_POLICY,
	    auditcmp_policy_event("system.Network"));
	ATF_CHECK_EQ(AUE_LOGCMP_POLICY,
	    auditcmp_policy_event("system.Log"));
	ATF_CHECK_EQ(AUE_BSDNOTIFY_POLICY,
	    auditcmp_policy_event("system.Notify"));
	ATF_CHECK_EQ(AUE_CRYPTOCMP_POLICY,
	    auditcmp_policy_event("system.Crypto"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("*"));
	ATF_CHECK_EQ(0, auditcmp_policy_event(""));
	ATF_CHECK_EQ(0, auditcmp_policy_event(NULL));
}

/*
 * A session's BSM event class is derived from its authenticated provider label,
 * and only from the whitelisted providers.  A whitelisted bundle id (optionally
 * carrying a "/<unit>" suffix, which is stripped) yields its real event class; a
 * non-whitelisted label yields event 0, which start_session() turns into an
 * EACCES refusal.  The match is on the exact bundle-id component, so a look-alike
 * label (a longer name sharing a prefix) does not inherit another provider's
 * class.
 */
ATF_TC_WITHOUT_HEAD(event_class_derives_from_authenticated_label);
ATF_TC_BODY(event_class_derives_from_authenticated_label, tc)
{

	(void)tc;
	/* Whitelisted provider, with and without a unit suffix. */
	ATF_CHECK_EQ(AUE_LOGCMP_POLICY, auditcmp_policy_event("system.Log"));
	ATF_CHECK_EQ(AUE_NETWORKCMP_POLICY,
	    auditcmp_policy_event("system.Network/collector"));
	ATF_CHECK_EQ(AUE_BSDNOTIFY_POLICY,
	    auditcmp_policy_event("system.Notify/agent.0"));
	ATF_CHECK_EQ(AUE_CRYPTOCMP_POLICY,
	    auditcmp_policy_event("system.Crypto/bsdcrypto"));

	/* Non-whitelisted labels derive event 0 -> the session is refused. */
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Trace"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("com.evil.Network"));
	/* Prefix look-alikes must not inherit a whitelisted provider's class. */
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Logger"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Lo"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Networking"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.Cryptography"));
}

/*
 * The auth agent's records carry their event class in the operation's first
 * path component: "elevate/<stage>[/<name>]" is AUE_AUTHAGENT_ELEVATE and
 * "mint/..." is AUE_AUTHAGENT_MINT.  backend_submit() refines the session's
 * admission event through auditcmp_policy_operation_event() per record.
 */
ATF_TC_WITHOUT_HEAD(operation_event_for_auth_agent);
ATF_TC_BODY(operation_event_for_auth_agent, tc)
{
	static const char *const elevate_ops[] = {
		"elevate", "elevate/", "elevate/policy",
		"elevate/policy/system.storage.admin",
		"elevate/password/system.notify.system",
		"elevate/ratelimit/system.notify.system",
		"elevate/caller", "elevate/shape", "elevate/mint/a.b",
		"elevate/ok/a.b", "elevate//",
	};
	static const char *const mint_ops[] = {
		"mint", "mint/", "mint/caller", "mint/shape", "mint/identity",
		"mint/user/n1", "mint/system/n0/all/admin/default",
		"mint/system/n32/admin",
	};
	unsigned i;

	(void)tc;
	/* The numbers are the registered ones. */
	ATF_CHECK_EQ(43335, AUE_AUTHAGENT_ELEVATE);
	ATF_CHECK_EQ(43336, AUE_AUTHAGENT_MINT);

	for (i = 0; i < nitems(elevate_ops); i++)
		ATF_CHECK_EQ_MSG(AUE_AUTHAGENT_ELEVATE,
		    auditcmp_policy_operation_event("system.Auth",
		    elevate_ops[i], 0), "operation %s", elevate_ops[i]);
	for (i = 0; i < nitems(mint_ops); i++)
		ATF_CHECK_EQ_MSG(AUE_AUTHAGENT_MINT,
		    auditcmp_policy_operation_event("system.Auth",
		    mint_ops[i], 0), "operation %s", mint_ops[i]);

	/* The fallback is ignored when the operation matches... */
	ATF_CHECK_EQ(AUE_AUTHAGENT_ELEVATE,
	    auditcmp_policy_operation_event("system.Auth", "elevate/x",
	    AUE_LOGCMP_POLICY));
	ATF_CHECK_EQ(AUE_AUTHAGENT_MINT,
	    auditcmp_policy_operation_event("system.Auth", "mint/x",
	    AUE_AUTHAGENT_ELEVATE));

	/* ...and the unit suffix on the label is stripped as for admission. */
	ATF_CHECK_EQ(AUE_AUTHAGENT_ELEVATE,
	    auditcmp_policy_operation_event("system.Auth/bsdauth",
	    "elevate/policy/a.b", 0));
	ATF_CHECK_EQ(AUE_AUTHAGENT_MINT,
	    auditcmp_policy_operation_event("system.Auth/bsdauth",
	    "mint/user/n1", 0));

	/* The session's admission event is the provider's first entry. */
	ATF_CHECK_EQ(AUE_AUTHAGENT_ELEVATE,
	    auditcmp_policy_event("system.Auth"));
	ATF_CHECK_EQ(AUE_AUTHAGENT_ELEVATE,
	    auditcmp_policy_event("system.Auth/bsdauth"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.AuthX"));
	ATF_CHECK_EQ(0, auditcmp_policy_event("system.AuthAgen"));
}

/*
 * An operation the per-operation provider does not list keeps the fallback:
 * a record is never dropped (or misfiled) for its operation text.  The
 * prefix match is exact on the first path component and case-sensitive.
 */
ATF_TC_WITHOUT_HEAD(operation_event_unknown_keeps_fallback);
ATF_TC_BODY(operation_event_unknown_keeps_fallback, tc)
{
	static const char *const unknown_ops[] = {
		"", "/", "rotate", "rotate/x", "elevated/x", "elevat/x",
		"Elevate/policy/a.b", "ELEVATE", "minting/x", "min/x",
		"Mint/user/n1", "/elevate", "/mint", " elevate", "elevate x",
		"x/elevate", "x/mint",
	};
	unsigned i;

	(void)tc;
	for (i = 0; i < nitems(unknown_ops); i++) {
		ATF_CHECK_EQ_MSG(AUE_AUTHAGENT_ELEVATE,
		    auditcmp_policy_operation_event("system.Auth",
		    unknown_ops[i], AUE_AUTHAGENT_ELEVATE),
		    "operation '%s' did not keep the fallback", unknown_ops[i]);
		ATF_CHECK_EQ_MSG(4242,
		    auditcmp_policy_operation_event("system.Auth",
		    unknown_ops[i], 4242),
		    "operation '%s' did not keep an arbitrary fallback",
		    unknown_ops[i]);
		ATF_CHECK_EQ_MSG(0,
		    auditcmp_policy_operation_event("system.Auth",
		    unknown_ops[i], 0),
		    "operation '%s' invented an event", unknown_ops[i]);
	}
	/* NULL operation or identity: the fallback, never a dereference. */
	ATF_CHECK_EQ(7, auditcmp_policy_operation_event("system.Auth",
	    NULL, 7));
	ATF_CHECK_EQ(7, auditcmp_policy_operation_event(NULL, "elevate/x", 7));
	ATF_CHECK_EQ(7, auditcmp_policy_operation_event(NULL, NULL, 7));
}

/*
 * Providers without per-operation entries are untouched: their admission
 * event is their only event, whatever the operation says -- including an
 * operation that spells "elevate" or "mint".  Look-alike labels get nothing.
 */
ATF_TC_WITHOUT_HEAD(operation_event_other_labels_unaffected);
ATF_TC_BODY(operation_event_other_labels_unaffected, tc)
{
	static const struct {
		const char	*identity;
		int		 event;
	} providers[] = {
		{ "system.Log", AUE_LOGCMP_POLICY },
		{ "system.Log/bsdlog", AUE_LOGCMP_POLICY },
		{ "system.Network", AUE_NETWORKCMP_POLICY },
		{ "system.Notify", AUE_BSDNOTIFY_POLICY },
		{ "system.Notify/bsdnotify", AUE_BSDNOTIFY_POLICY },
		{ "system.Crypto", AUE_CRYPTOCMP_POLICY },
	};
	static const char *const ops[] = {
		"elevate", "elevate/policy/a.b", "mint", "mint/user/n1",
		"admit", "admit-tier-mismatch-open", "publish", "",
	};
	unsigned i, j;

	(void)tc;
	for (i = 0; i < nitems(providers); i++) {
		/* Admission is unchanged. */
		ATF_CHECK_EQ(providers[i].event,
		    auditcmp_policy_event(providers[i].identity));
		for (j = 0; j < nitems(ops); j++) {
			ATF_CHECK_EQ_MSG(providers[i].event,
			    auditcmp_policy_operation_event(providers[i].identity,
			    ops[j], providers[i].event),
			    "%s %s changed its event", providers[i].identity,
			    ops[j]);
			/* Whatever fallback the session carries is kept. */
			ATF_CHECK_EQ_MSG(9999,
			    auditcmp_policy_operation_event(providers[i].identity,
			    ops[j], 9999),
			    "%s %s replaced the session fallback",
			    providers[i].identity, ops[j]);
		}
	}
	/* Non-whitelisted and look-alike labels never gain the agent's classes. */
	ATF_CHECK_EQ(0, auditcmp_policy_operation_event("com.evil.AuthAgent",
	    "elevate/policy/a.b", 0));
	ATF_CHECK_EQ(0, auditcmp_policy_operation_event("system.AuthX",
	    "mint/user/n1", 0));
	ATF_CHECK_EQ(0, auditcmp_policy_operation_event("system.Auth",
	    "elevate", 0));
	ATF_CHECK_EQ(0, auditcmp_policy_operation_event("system.AuthAgen",
	    "elevate", 0));
	ATF_CHECK_EQ(0, auditcmp_policy_operation_event("",
	    "elevate", 0));
	ATF_CHECK_EQ(0, auditcmp_policy_operation_event("*", "mint", 0));
	/* A per-operation class is never handed to a session whose admission
	 * failed (event 0) merely because the operation text matches. */
	ATF_CHECK_EQ(0, auditcmp_policy_operation_event("system.Trace",
	    "elevate/policy/a.b", 0));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, identity_map);
	ATF_TP_ADD_TC(tp, event_class_derives_from_authenticated_label);
	ATF_TP_ADD_TC(tp, operation_event_for_auth_agent);
	ATF_TP_ADD_TC(tp, operation_event_unknown_keeps_fallback);
	ATF_TP_ADD_TC(tp, operation_event_other_labels_unaffected);
	return (atf_no_error());
}
