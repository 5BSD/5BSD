/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Reclaim-gate authenticity (docs/capability-lifecycle-cleanup.md).
 *
 * Label reclaim has TWO independent guards, and this pins both:
 *
 *  1. The ambient operator entry point SCTL_OP_RECLAIM is ADMIN-gated exactly
 *     like start/stop: a
 *     non-admin control caller gets EPERM (sctl.c / sctl_gate.h).
 *
 *  2. Reclaim is switchboard-ORIGINATED only.  SVC_OP_RECLAIM_LABEL is a
 *     switchboard -> service NOTIFICATION (op band >= 127); it is NOT one of the
 *     service -> switchboard request ops (band 1..12) the inbound dispatcher
 *     (svc_proto.c svc_request) handles, so a service that sends it is answered
 *     ENOTSUP by the dispatcher default.  A service can never ask switchboard to
 *     retire a label.  Asserted here as the wire-contract invariant the
 *     dispatcher relies on.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "switchboard_svc_proto.h"		/* SVC_OP_* opcode bands */
#include "switchboard.h"			/* SVC_STATE_* */
#include "sctl_gate.h"
#include "reclaim_gate.h"

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
 * Guard 2 — reclaim is switchboard-originated only.  SVC_OP_RECLAIM_LABEL lives in
 * the switchboard -> service notification band and is disjoint from every
 * service -> switchboard request op the inbound dispatcher accepts, so an inbound
 * request carrying it can only fall through to the dispatcher's ENOTSUP
 * default.  A service can never trigger a label retirement.
 */
ATF_TC_WITHOUT_HEAD(reclaim_label_is_not_an_inbound_request_op);
ATF_TC_BODY(reclaim_label_is_not_an_inbound_request_op, tc)
{
	/* Every op the service -> switchboard dispatcher (svc_request) handles. */
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

	/* It is a switchboard -> service notification (>= the notification band). */
	ATF_CHECK_MSG(SVC_OP_RECLAIM_LABEL >= SVC_OP_NEW_CLIENT,
	    "SVC_OP_RECLAIM_LABEL must be in the switchboard->service notification "
	    "band, not the request band");

	/* And it collides with NO inbound service-request op. */
	for (i = 0; i < nitems(inbound_request_ops); i++)
		ATF_CHECK_MSG(SVC_OP_RECLAIM_LABEL != inbound_request_ops[i],
		    "SVC_OP_RECLAIM_LABEL must not alias inbound request op %u",
		    inbound_request_ops[i]);
}

/*
 * Guard 3 — the operator reclaim label must be non-empty and fit the reclaim
 * notification's fixed label[] field with room for its NUL.  This pins the
 * length edges sctl.c's SCTL_OP_RECLAIM handler enforces via
 * svc_reclaim_label_len_ok().
 */
ATF_TC_WITHOUT_HEAD(reclaim_label_len_edges);
ATF_TC_BODY(reclaim_label_len_edges, tc)
{
	const size_t fieldsz =
	    sizeof(((struct svc_reclaim_label_msg *)0)->label);

	/* Empty label: nothing to reclaim => invalid (sctl.c EINVAL). */
	ATF_CHECK_MSG(!svc_reclaim_label_len_ok(0),
	    "a zero-length reclaim label must be rejected");

	/* Minimum valid label. */
	ATF_CHECK_MSG(svc_reclaim_label_len_ok(1),
	    "a one-byte reclaim label must be accepted");

	/* Longest label that still leaves room for the NUL. */
	ATF_CHECK_MSG(svc_reclaim_label_len_ok(fieldsz - 1),
	    "a label of field size minus one must be accepted");

	/* Exactly the field size: no room for the NUL => invalid. */
	ATF_CHECK_MSG(!svc_reclaim_label_len_ok(fieldsz),
	    "a label filling the whole field (no NUL room) must be rejected");

	/* Absurdly long => invalid. */
	ATF_CHECK_MSG(!svc_reclaim_label_len_ok(fieldsz + 4096),
	    "an oversized reclaim label must be rejected");
}

/*
 * Guard 4 — the reclaim notification fans out to RUNNING providers with a live
 * control channel only.  This pins the per-service skip in
 * reload.c svc_retire_label() via svc_reclaim_notify_target().
 */
ATF_TC_WITHOUT_HEAD(reclaim_notify_target_selection);
ATF_TC_BODY(reclaim_notify_target_selection, tc)
{

	/* RUNNING with a channel is the only case that receives the push. */
	ATF_CHECK_MSG(svc_reclaim_notify_target(SVC_STATE_RUNNING, true),
	    "a RUNNING service with a control channel must be a target");

	/* RUNNING but no channel: skipped. */
	ATF_CHECK_MSG(!svc_reclaim_notify_target(SVC_STATE_RUNNING, false),
	    "a RUNNING service without a control channel must be skipped");

	/* Any non-RUNNING state, even with a channel: skipped. */
	ATF_CHECK_MSG(!svc_reclaim_notify_target(SVC_STATE_STOPPED, true),
	    "a STOPPED service must be skipped");
	ATF_CHECK_MSG(!svc_reclaim_notify_target(SVC_STATE_STARTING, true),
	    "a STARTING service must be skipped");
	ATF_CHECK_MSG(!svc_reclaim_notify_target(SVC_STATE_STOPPING, true),
	    "a STOPPING service must be skipped");
	ATF_CHECK_MSG(!svc_reclaim_notify_target(SVC_STATE_DONE, true),
	    "a DONE service must be skipped");
}

/* Guard 5 — zero recipients is a retryable delivery failure. */
ATF_TC_WITHOUT_HEAD(reclaim_delivery_requires_a_recipient);
ATF_TC_BODY(reclaim_delivery_requires_a_recipient, tc)
{

	ATF_CHECK_EQ(EAGAIN, svc_reclaim_delivery_status(0));
	ATF_CHECK_EQ(0, svc_reclaim_delivery_status(1));
	ATF_CHECK_EQ(0, svc_reclaim_delivery_status(100));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, reclaim_op_admin_gated);
	ATF_TP_ADD_TC(tp, reclaim_label_is_not_an_inbound_request_op);
	ATF_TP_ADD_TC(tp, reclaim_label_len_edges);
	ATF_TP_ADD_TC(tp, reclaim_notify_target_selection);
	ATF_TP_ADD_TC(tp, reclaim_delivery_requires_a_recipient);

	return (atf_no_error());
}
