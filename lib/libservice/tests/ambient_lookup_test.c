/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice private-lookup registration fail-soft decision
 * (docs/capability-ambient-lookup-per-process.md, P2).
 *
 * On first ambient use a process tries to register a private lookup channel;
 * these cases pin the pure fail-soft decision (service_ambient_reg_decide,
 * ambient_lookup.h): ONLY an all-green create+send+ack path uses the private
 * channel, and ANY failure — no create syscall (ENOSYS on an old kernel), a
 * send error, or a missing/invalid/late ACK — falls back to the inherited
 * shared channel.  Header-only, no live plane.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>

#include "ambient_lookup.h"

/* All three steps green => use the private channel. */
ATF_TC_WITHOUT_HEAD(all_green_uses_private);
ATF_TC_BODY(all_green_uses_private, tc)
{

	ATF_CHECK_EQ_MSG(SERVICE_AMBIENT_USE_PRIVATE,
	    service_ambient_reg_decide(0, true, true),
	    "create+send+ack all succeeding must use the private channel");
}

/*
 * The create syscall is missing (old kernel): create_errno == ENOSYS, so send
 * and ack never happen (false).  Fall back to the inherited shared channel —
 * this is the rollout-safety path.
 */
ATF_TC_WITHOUT_HEAD(no_syscall_falls_back);
ATF_TC_BODY(no_syscall_falls_back, tc)
{

	ATF_CHECK_EQ_MSG(SERVICE_AMBIENT_USE_INHERITED,
	    service_ambient_reg_decide(ENOSYS, false, false),
	    "a missing create syscall must fall back to the shared channel");
	/* Any create errno at all, not just ENOSYS, falls back. */
	ATF_CHECK_EQ(SERVICE_AMBIENT_USE_INHERITED,
	    service_ambient_reg_decide(EMFILE, false, false));
}

/* The pair was made but the registration send failed => fall back. */
ATF_TC_WITHOUT_HEAD(send_failure_falls_back);
ATF_TC_BODY(send_failure_falls_back, tc)
{

	ATF_CHECK_EQ_MSG(SERVICE_AMBIENT_USE_INHERITED,
	    service_ambient_reg_decide(0, false, false),
	    "a failed registration send must fall back to the shared channel");
}

/*
 * The send succeeded but no valid ACK arrived (timeout, wrong magic, wrong op,
 * short reply) => fall back.  This is the wedged-serviced path.
 */
ATF_TC_WITHOUT_HEAD(no_ack_falls_back);
ATF_TC_BODY(no_ack_falls_back, tc)
{

	ATF_CHECK_EQ_MSG(SERVICE_AMBIENT_USE_INHERITED,
	    service_ambient_reg_decide(0, true, false),
	    "a missing/invalid ACK must fall back to the shared channel");
}

/*
 * The decision must never return PRIVATE unless the create actually succeeded:
 * even the (impossible-in-practice) send/ack-true-after-create-failure shape
 * still falls back, so a create failure can never be overridden downstream.
 */
ATF_TC_WITHOUT_HEAD(create_failure_dominates);
ATF_TC_BODY(create_failure_dominates, tc)
{

	ATF_CHECK_EQ(SERVICE_AMBIENT_USE_INHERITED,
	    service_ambient_reg_decide(ENOSYS, true, true));
	ATF_CHECK_EQ(SERVICE_AMBIENT_USE_INHERITED,
	    service_ambient_reg_decide(ENOSYS, true, false));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, all_green_uses_private);
	ATF_TP_ADD_TC(tp, no_syscall_falls_back);
	ATF_TP_ADD_TC(tp, send_failure_falls_back);
	ATF_TP_ADD_TC(tp, no_ack_falls_back);
	ATF_TP_ADD_TC(tp, create_failure_dominates);

	return (atf_no_error());
}
