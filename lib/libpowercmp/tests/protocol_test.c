/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire-contract tests for powercmp_validate_message -- the shared guard the
 * client and the BSDTime daemon both run on every received message.
 */
#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "powercmp_protocol.h"

static void
init(struct powercmp_msg *m, uint32_t op)
{

	memset(m, 0, sizeof(*m));
	m->magic = POWERCMP_MAGIC;
	m->opcode = op;
}

ATF_TC_WITHOUT_HEAD(bare_header_is_valid);
ATF_TC_BODY(bare_header_is_valid, tc)
{
	struct powercmp_msg m;

	init(&m, POWERCMP_OP_STATES);
	ATF_CHECK_EQ(0, powercmp_validate_message(&m, sizeof(m),
	    POWERCMP_MESSAGE_REQUEST));
}

ATF_TC_WITHOUT_HEAD(header_plus_one_time_is_valid);
ATF_TC_BODY(header_plus_one_time_is_valid, tc)
{
	uint8_t buf[POWERCMP_MAX_MESSAGE];
	struct powercmp_msg *m = (void *)buf;

	memset(buf, 0, sizeof(buf));
	init(m, POWERCMP_OP_SUSPEND);
	ATF_CHECK_EQ(0, powercmp_validate_message(m,
	    sizeof(*m) + sizeof(struct powercmp_body), POWERCMP_MESSAGE_REQUEST));
}

ATF_TC_WITHOUT_HEAD(bad_magic_is_rejected);
ATF_TC_BODY(bad_magic_is_rejected, tc)
{
	struct powercmp_msg m;

	init(&m, POWERCMP_OP_STATES);
	m.magic = 0xdeadbeef;
	ATF_CHECK_EQ(-1, powercmp_validate_message(&m, sizeof(m),
	    POWERCMP_MESSAGE_REQUEST));
}

ATF_TC_WITHOUT_HEAD(unknown_opcode_is_rejected);
ATF_TC_BODY(unknown_opcode_is_rejected, tc)
{
	struct powercmp_msg m;

	init(&m, 0);
	ATF_CHECK_EQ(-1, powercmp_validate_message(&m, sizeof(m),
	    POWERCMP_MESSAGE_REQUEST));
	init(&m, 999);
	ATF_CHECK_EQ(-1, powercmp_validate_message(&m, sizeof(m),
	    POWERCMP_MESSAGE_REQUEST));
}

ATF_TC_WITHOUT_HEAD(odd_lengths_are_rejected);
ATF_TC_BODY(odd_lengths_are_rejected, tc)
{
	uint8_t buf[POWERCMP_MAX_MESSAGE + 8];
	struct powercmp_msg *m = (void *)buf;

	init(m, POWERCMP_OP_STATES);
	/* shorter than a header */
	ATF_CHECK_EQ(-1, powercmp_validate_message(m, sizeof(*m) - 1,
	    POWERCMP_MESSAGE_REQUEST));
	/* header + a partial body */
	ATF_CHECK_EQ(-1, powercmp_validate_message(m, sizeof(*m) + 4,
	    POWERCMP_MESSAGE_REQUEST));
	/* header + more than one body */
	ATF_CHECK_EQ(-1, powercmp_validate_message(m,
	    sizeof(*m) + 2 * sizeof(struct powercmp_body),
	    POWERCMP_MESSAGE_REQUEST));
}

ATF_TC_WITHOUT_HEAD(reply_with_positive_status_is_rejected);
ATF_TC_BODY(reply_with_positive_status_is_rejected, tc)
{
	struct powercmp_msg m;

	init(&m, POWERCMP_OP_SUSPEND);
	m.status = 1;		/* replies carry 0 or -errno, never +ve */
	ATF_CHECK_EQ(-1, powercmp_validate_message(&m, sizeof(m),
	    POWERCMP_MESSAGE_REPLY));
	/* Requests cannot smuggle reply status. */
	ATF_CHECK_EQ(-1, powercmp_validate_message(&m, sizeof(m),
	    POWERCMP_MESSAGE_REQUEST));
}

ATF_TC_WITHOUT_HEAD(lease_framing);
ATF_TC_BODY(lease_framing, tc)
{
	struct {
		struct powercmp_msg m;
		struct powercmp_body body;
	} frame = { 0 };
	struct powercmp_msg *m = &frame.m;
	init(m, POWERCMP_OP_INHIBIT);
	ATF_CHECK_EQ(0,
	    powercmp_validate_message(m, sizeof(*m), POWERCMP_MESSAGE_REQUEST));
	ATF_CHECK_EQ(-1,
	    powercmp_validate_message(m, sizeof(frame),
		POWERCMP_MESSAGE_REQUEST));
	m->flags = 1;
	ATF_CHECK_EQ(-1,
	    powercmp_validate_message(m, sizeof(*m), POWERCMP_MESSAGE_REQUEST));
	m->flags = 0;
	m->status = 1;
	ATF_CHECK_EQ(-1,
	    powercmp_validate_message(m, sizeof(*m), POWERCMP_MESSAGE_REQUEST));
	init(m, POWERCMP_OP_INHIBITORS);
	ATF_CHECK_EQ(-1,
	    powercmp_validate_message(m, sizeof(*m), POWERCMP_MESSAGE_REPLY));
	ATF_CHECK_EQ(0,
	    powercmp_validate_message(m, sizeof(frame),
		POWERCMP_MESSAGE_REPLY));
	m->status = -1;
	ATF_CHECK_EQ(0,
	    powercmp_validate_message(m, sizeof(*m), POWERCMP_MESSAGE_REPLY));
}
ATF_TC_WITHOUT_HEAD(all_operations_have_exact_frames);
ATF_TC_BODY(all_operations_have_exact_frames, tc)
{
	struct {
		struct powercmp_msg m;
		struct powercmp_body body;
	} frame;
	for (unsigned op = POWERCMP_OP_STATES; op <= POWERCMP_OP_INHIBITORS;
	    op++) {
		memset(&frame, 0, sizeof(frame));
		init(&frame.m, op);
		size_t request = sizeof(frame.m) +
		    (op == POWERCMP_OP_SUSPEND ? sizeof(frame.body) : 0);
		size_t response = sizeof(frame.m) +
		    ((op == POWERCMP_OP_STATES ||
			 op == POWERCMP_OP_INHIBITORS) ?
			    sizeof(frame.body) :
			    0);
		ATF_CHECK_EQ(0,
		    powercmp_validate_message(&frame.m, request,
			POWERCMP_MESSAGE_REQUEST));
		ATF_CHECK_EQ(0,
		    powercmp_validate_message(&frame.m, response,
			POWERCMP_MESSAGE_REPLY));
		ATF_CHECK_EQ(-1,
		    powercmp_validate_message(&frame.m, request, 99));
		frame.m.flags = 1;
		ATF_CHECK_EQ(-1,
		    powercmp_validate_message(&frame.m, request,
			POWERCMP_MESSAGE_REQUEST));
		frame.m.flags = 0;
		frame.m.status = -EPERM;
		ATF_CHECK_EQ(-1,
		    powercmp_validate_message(&frame.m, request,
			POWERCMP_MESSAGE_REQUEST));
		ATF_CHECK_EQ(0,
		    powercmp_validate_message(&frame.m, sizeof(frame.m),
			POWERCMP_MESSAGE_REPLY));
		ATF_CHECK_EQ(-1,
		    powercmp_validate_message(&frame.m, sizeof(frame),
			POWERCMP_MESSAGE_REPLY));
	}
	memset(&frame, 0, sizeof(frame));
	init(&frame.m, POWERCMP_OP_SUSPEND);
	frame.body.reserved[0] = 1;
	ATF_CHECK_EQ(-1,
	    powercmp_validate_message(&frame.m, sizeof(frame),
		POWERCMP_MESSAGE_REQUEST));
	frame.body.reserved[0] = 0;
	frame.body.supported = 1;
	ATF_CHECK_EQ(-1,
	    powercmp_validate_message(&frame.m, sizeof(frame),
		POWERCMP_MESSAGE_REQUEST));
	init(&frame.m, POWERCMP_OP_STATES);
	frame.body.state = 1;
	ATF_CHECK_EQ(-1,
	    powercmp_validate_message(&frame.m, sizeof(frame),
		POWERCMP_MESSAGE_REPLY));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lease_framing);
	ATF_TP_ADD_TC(tp, all_operations_have_exact_frames);
	ATF_TP_ADD_TC(tp, bare_header_is_valid);
	ATF_TP_ADD_TC(tp, header_plus_one_time_is_valid);
	ATF_TP_ADD_TC(tp, bad_magic_is_rejected);
	ATF_TP_ADD_TC(tp, unknown_opcode_is_rejected);
	ATF_TP_ADD_TC(tp, odd_lengths_are_rejected);
	ATF_TP_ADD_TC(tp, reply_with_positive_status_is_rejected);
	return (atf_no_error());
}
