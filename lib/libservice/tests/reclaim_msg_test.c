/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the libservice inbound reclaim-notification message validator
 * (reclaim_msg.h, docs/capability-lifecycle-cleanup.md).  Header-only: the
 * predicate is pure, so no live plane or running serviced is needed.  The
 * dispatch path in libservice.c invokes a provider's reclaim handler only when
 * this predicate accepts the received message (plus a handler != NULL runtime
 * check kept at the call site); these cases pin the fail-closed shape check.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "serviced_svc_proto.h"		/* struct svc_reclaim_label_msg, SVC_OP_* */
#include "reclaim_msg.h"

/* A canonically well-formed reclaim notification. */
static struct svc_reclaim_label_msg
good_msg(void)
{
	struct svc_reclaim_label_msg m;

	memset(&m, 0, sizeof(m));
	m.op = SVC_OP_RECLAIM_LABEL;
	m.flags = 0;
	strlcpy(m.label, "com.example.bundle", sizeof(m.label));
	return (m);
}

/* A correctly shaped message is accepted. */
ATF_TC_WITHOUT_HEAD(reclaim_msg_accepts_valid);
ATF_TC_BODY(reclaim_msg_accepts_valid, tc)
{
	struct svc_reclaim_label_msg m = good_msg();

	ATF_CHECK_MSG(service_reclaim_msg_valid(&m, sizeof(m)),
	    "a well-formed reclaim notification must be accepted");
}

/* Wrong op => rejected. */
ATF_TC_WITHOUT_HEAD(reclaim_msg_rejects_wrong_op);
ATF_TC_BODY(reclaim_msg_rejects_wrong_op, tc)
{
	struct svc_reclaim_label_msg m = good_msg();

	m.op = SVC_OP_RECLAIM_LABEL + 1;
	ATF_CHECK_MSG(!service_reclaim_msg_valid(&m, sizeof(m)),
	    "a message with the wrong op must be rejected");
}

/* Reserved flags set => rejected. */
ATF_TC_WITHOUT_HEAD(reclaim_msg_rejects_nonzero_flags);
ATF_TC_BODY(reclaim_msg_rejects_nonzero_flags, tc)
{
	struct svc_reclaim_label_msg m = good_msg();

	m.flags = 1;
	ATF_CHECK_MSG(!service_reclaim_msg_valid(&m, sizeof(m)),
	    "a message with reserved flags set must be rejected");
}

/* Unterminated label (every byte non-zero) => rejected. */
ATF_TC_WITHOUT_HEAD(reclaim_msg_rejects_unterminated_label);
ATF_TC_BODY(reclaim_msg_rejects_unterminated_label, tc)
{
	struct svc_reclaim_label_msg m = good_msg();

	memset(m.label, 'A', sizeof(m.label));	/* no NUL anywhere */
	ATF_CHECK_MSG(!service_reclaim_msg_valid(&m, sizeof(m)),
	    "a label with no NUL terminator must be rejected");
}

/* Wrong declared message length => rejected. */
ATF_TC_WITHOUT_HEAD(reclaim_msg_rejects_wrong_len);
ATF_TC_BODY(reclaim_msg_rejects_wrong_len, tc)
{
	struct svc_reclaim_label_msg m = good_msg();

	ATF_CHECK_MSG(!service_reclaim_msg_valid(&m, sizeof(m) - 1),
	    "a short message length must be rejected");
	ATF_CHECK_MSG(!service_reclaim_msg_valid(&m, sizeof(m) + 1),
	    "an over-long message length must be rejected");
	ATF_CHECK_MSG(!service_reclaim_msg_valid(&m, 0),
	    "a zero message length must be rejected");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, reclaim_msg_accepts_valid);
	ATF_TP_ADD_TC(tp, reclaim_msg_rejects_wrong_op);
	ATF_TP_ADD_TC(tp, reclaim_msg_rejects_nonzero_flags);
	ATF_TP_ADD_TC(tp, reclaim_msg_rejects_unterminated_label);
	ATF_TP_ADD_TC(tp, reclaim_msg_rejects_wrong_len);

	return (atf_no_error());
}
