/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Private-lookup-channel adoption decision
 * (docs/capability-ambient-lookup-per-process.md, P2).
 *
 * SVC_OP_REGISTER_LOOKUP lets a process hand switchboard one endpoint of a channel
 * pair it made for itself, which switchboard adopts as that process's private
 * lookup channel.  These cases pin the pure part of that decision
 * (svc_register_lookup_check, register_lookup_gate.h): the wire-shape rules and
 * — the security-critical invariant — that the adopted domain is ALWAYS the
 * domain of the channel the request arrived on, never widened.  Header-only, no
 * live daemon.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#include "switchboard_svc_proto.h"		/* struct svc_register_lookup_req */
#include "switchboard.h"			/* enum svc_domain_kind */
#include "register_lookup_gate.h"

#define	GOOD_LEN	(sizeof(struct svc_register_lookup_req))

/*
 * The happy path: exactly one attached descriptor that is a channel, correct
 * length, zero flags.  Adoption succeeds and the adopted domain equals the
 * arriving domain for EVERY domain kind — SYSTEM stays SYSTEM, USER stays USER,
 * CONTROL stays CONTROL.  This is the no-widening invariant.
 */
ATF_TC_WITHOUT_HEAD(adopt_domain_is_arriving_domain);
ATF_TC_BODY(adopt_domain_is_arriving_domain, tc)
{
	const enum svc_domain_kind kinds[] = {
		SVC_DOMAIN_SYSTEM, SVC_DOMAIN_USER, SVC_DOMAIN_CONTROL
	};
	enum svc_domain_kind adopt;
	unsigned i;

	for (i = 0; i < nitems(kinds); i++) {
		adopt = (enum svc_domain_kind)0xdead;
		ATF_CHECK_EQ_MSG(0, svc_register_lookup_check(GOOD_LEN, 1, true,
		    0, kinds[i], &adopt),
		    "a well-formed request must be accepted");
		ATF_CHECK_EQ_MSG(kinds[i], adopt,
		    "the adopted domain must equal the arriving domain (no widening)");
	}
}

/*
 * A USER channel can never register a SYSTEM (wider) scope: the decision derives
 * the adopted domain ONLY from the arriving channel, and there is no wire field
 * that could carry a domain at all.  Pin it explicitly: a USER arrival adopts
 * USER, never SYSTEM.
 */
ATF_TC_WITHOUT_HEAD(user_cannot_widen_to_system);
ATF_TC_BODY(user_cannot_widen_to_system, tc)
{
	enum svc_domain_kind adopt = (enum svc_domain_kind)0xdead;

	ATF_CHECK_EQ(0, svc_register_lookup_check(GOOD_LEN, 1, true, 0,
	    SVC_DOMAIN_USER, &adopt));
	ATF_CHECK_EQ_MSG(SVC_DOMAIN_USER, adopt,
	    "a USER arrival must adopt USER, never widen to SYSTEM");
	ATF_CHECK_MSG(adopt != SVC_DOMAIN_SYSTEM,
	    "a USER arrival must never adopt SYSTEM");
}

/* Zero descriptors: nothing to adopt => EINVAL, adopt untouched. */
ATF_TC_WITHOUT_HEAD(reject_zero_fds);
ATF_TC_BODY(reject_zero_fds, tc)
{
	enum svc_domain_kind adopt = SVC_DOMAIN_USER;

	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(GOOD_LEN, 0, true, 0,
	    SVC_DOMAIN_SYSTEM, &adopt));
	ATF_CHECK_EQ_MSG(SVC_DOMAIN_USER, adopt,
	    "adopt must be left untouched on rejection");
}

/* More than one descriptor: ambiguous => EINVAL. */
ATF_TC_WITHOUT_HEAD(reject_multi_fd);
ATF_TC_BODY(reject_multi_fd, tc)
{
	enum svc_domain_kind adopt;

	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(GOOD_LEN, 2, true, 0,
	    SVC_DOMAIN_SYSTEM, &adopt));
	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(GOOD_LEN, 8, true, 0,
	    SVC_DOMAIN_SYSTEM, &adopt));
}

/* The single descriptor is not a mac_capability channel => EINVAL. */
ATF_TC_WITHOUT_HEAD(reject_non_channel_fd);
ATF_TC_BODY(reject_non_channel_fd, tc)
{
	enum svc_domain_kind adopt;

	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(GOOD_LEN, 1, false, 0,
	    SVC_DOMAIN_SYSTEM, &adopt));
}

/* Wrong payload length (short or long) => EINVAL, even with a valid fd. */
ATF_TC_WITHOUT_HEAD(reject_bad_length);
ATF_TC_BODY(reject_bad_length, tc)
{
	enum svc_domain_kind adopt;

	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(GOOD_LEN - 1, 1, true, 0,
	    SVC_DOMAIN_SYSTEM, &adopt));
	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(GOOD_LEN + 4, 1, true, 0,
	    SVC_DOMAIN_SYSTEM, &adopt));
	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(0, 1, true, 0,
	    SVC_DOMAIN_SYSTEM, &adopt));
}

/* Reserved flags must be zero => EINVAL otherwise. */
ATF_TC_WITHOUT_HEAD(reject_nonzero_flags);
ATF_TC_BODY(reject_nonzero_flags, tc)
{
	enum svc_domain_kind adopt;

	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(GOOD_LEN, 1, true, 1,
	    SVC_DOMAIN_SYSTEM, &adopt));
	ATF_CHECK_EQ(EINVAL, svc_register_lookup_check(GOOD_LEN, 1, true,
	    0xffffffffU, SVC_DOMAIN_SYSTEM, &adopt));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, adopt_domain_is_arriving_domain);
	ATF_TP_ADD_TC(tp, user_cannot_widen_to_system);
	ATF_TP_ADD_TC(tp, reject_zero_fds);
	ATF_TP_ADD_TC(tp, reject_multi_fd);
	ATF_TP_ADD_TC(tp, reject_non_channel_fd);
	ATF_TP_ADD_TC(tp, reject_bad_length);
	ATF_TP_ADD_TC(tp, reject_nonzero_flags);

	return (atf_no_error());
}
