/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Reclaim-gate authenticity (docs/capability-lifecycle-cleanup.md).
 *
 * Label reclaim has TWO independent guards, and this pins both:
 *
 *  1. The operator entry point SCTL_OP_RECLAIM (servicectl reclaim, driven by
 *     the pkg deinstall hook) is ADMIN-gated exactly like start/stop: a
 *     non-admin control caller gets EPERM (sctl.c / sctl_gate.h).
 *
 *  2. Reclaim is serviced-ORIGINATED only.  SVC_OP_RECLAIM_LABEL is a
 *     serviced -> service NOTIFICATION (op band >= 127); it is NOT one of the
 *     service -> serviced request ops (band 1..12) the inbound dispatcher
 *     (svc_proto.c svc_request) handles, so a service that sends it is answered
 *     ENOTSUP by the dispatcher default.  A service can never ask serviced to
 *     retire a label.  Asserted here as the wire-contract invariant the
 *     dispatcher relies on.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "serviced_svc_proto.h"		/* SVC_OP_* opcode bands */
#include "sctl_gate.h"

/*
 * Guard 1 — the operator reclaim op is admin-gated: a non-admin caller is
 * denied with EPERM, an admin caller passes the rights gate.
 */
ATF_TC_WITHOUT_HEAD(reclaim_op_admin_gated);
ATF_TC_BODY(reclaim_op_admin_gated, tc)
{

	ATF_CHECK_MSG(sctl_op_requires_admin(SCTL_OP_RECLAIM),
	    "SCTL_OP_RECLAIM must require the ADMIN right");

	/* Non-admin => denied. */
	ATF_CHECK_MSG(sctl_op_requires_admin(SCTL_OP_RECLAIM) &&
	    !sctl_rights_is_admin(SVC_RIGHTS_ALL & ~SVC_RIGHTS_ADMIN),
	    "a non-admin caller must be denied SCTL_OP_RECLAIM (EPERM)");
	ATF_CHECK_MSG(sctl_op_requires_admin(SCTL_OP_RECLAIM) &&
	    !sctl_rights_is_admin(0),
	    "an empty-grant caller must be denied SCTL_OP_RECLAIM (EPERM)");

	/* Admin => passes the rights gate. */
	ATF_CHECK_MSG(!(sctl_op_requires_admin(SCTL_OP_RECLAIM) &&
	    !sctl_rights_is_admin(SVC_RIGHTS_ADMIN)),
	    "an admin caller must pass the rights gate for SCTL_OP_RECLAIM");
}

/*
 * Guard 2 — reclaim is serviced-originated only.  SVC_OP_RECLAIM_LABEL lives in
 * the serviced -> service notification band and is disjoint from every
 * service -> serviced request op the inbound dispatcher accepts, so an inbound
 * request carrying it can only fall through to the dispatcher's ENOTSUP
 * default.  A service can never trigger a label retirement.
 */
ATF_TC_WITHOUT_HEAD(reclaim_label_is_not_an_inbound_request_op);
ATF_TC_BODY(reclaim_label_is_not_an_inbound_request_op, tc)
{
	/* Every op the service -> serviced dispatcher (svc_request) handles. */
	const uint32_t inbound_request_ops[] = {
		SVC_OP_READY,
		SVC_OP_NAME_RESULT,
		SVC_OP_NAME_WITHDRAW,
		SVC_OP_LOOKUP,
		SVC_OP_NAME_CLAIM,
		SVC_OP_QUIESCE_RESULT,
		SVC_OP_WORKER_CHANNEL,
		SVC_OP_IDLE,
		SVC_OP_MINT_DOMAIN,
		SVC_OP_AMBIENT_HELLO,
		SVC_OP_HELPER_OPEN,
		SVC_OP_LABEL_IS_LIVE,
	};
	unsigned i;

	/* It is a serviced -> service notification (>= the notification band). */
	ATF_CHECK_MSG(SVC_OP_RECLAIM_LABEL >= SVC_OP_NEW_CLIENT,
	    "SVC_OP_RECLAIM_LABEL must be in the serviced->service notification "
	    "band, not the request band");

	/* And it collides with NO inbound service-request op. */
	for (i = 0; i < nitems(inbound_request_ops); i++)
		ATF_CHECK_MSG(SVC_OP_RECLAIM_LABEL != inbound_request_ops[i],
		    "SVC_OP_RECLAIM_LABEL must not alias inbound request op %u",
		    inbound_request_ops[i]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, reclaim_op_admin_gated);
	ATF_TP_ADD_TC(tp, reclaim_label_is_not_an_inbound_request_op);

	return (atf_no_error());
}
