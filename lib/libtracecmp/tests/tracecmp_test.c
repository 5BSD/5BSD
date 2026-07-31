/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "tracecmp.h"

static struct tracecmp_msg
message(uint16_t opcode)
{
	struct tracecmp_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.magic = TRACECMP_MAGIC;
	msg.version = TRACECMP_ABI_VERSION;
	msg.opcode = opcode;
	return (msg);
}

ATF_TC(abi);
ATF_TC_HEAD(abi, tc)
{
	atf_tc_set_md_var(tc, "descr", "TraceCmp wire ABI remains fixed");
}
ATF_TC_BODY(abi, tc)
{
	ATF_CHECK_EQ(16, sizeof(struct tracecmp_msg));
	ATF_CHECK_EQ(16, sizeof(struct tracecmp_hello_reply));
	ATF_CHECK_EQ(32, sizeof(struct tracecmp_stats));
	ATF_CHECK_EQ(3, TRACECMP_OP_STATS);
}

ATF_TC(validation);
ATF_TC_HEAD(validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "TraceCmp rejects malformed frames and descriptor confusion");
}
ATF_TC_BODY(validation, tc)
{
	struct {
		struct tracecmp_msg msg;
		struct tracecmp_hello_reply hello;
	} wire;

	memset(&wire, 0, sizeof(wire));
	wire.msg = message(TRACECMP_OP_HELLO);
	wire.hello.version = TRACECMP_ABI_VERSION;
	wire.hello.features = TRACECMP_FEATURE_RAW_DTRACE_FD;
	ATF_CHECK_EQ(0, tracecmp_validate_message(&wire.msg, sizeof(wire),
	    TRACECMP_MESSAGE_REPLY));
	ATF_CHECK_EQ(0, tracecmp_validate_fds(&wire.msg, 0,
	    TRACECMP_MESSAGE_REPLY));
	wire.hello.features = 0;
	ATF_CHECK_EQ(0, tracecmp_validate_message(&wire.msg, sizeof(wire),
	    TRACECMP_MESSAGE_REPLY));
	wire.hello.features = UINT32_C(0x80000000);
	ATF_CHECK_EQ(-1, tracecmp_validate_message(&wire.msg, sizeof(wire),
	    TRACECMP_MESSAGE_REPLY));

	wire.msg = message(TRACECMP_OP_OPEN);
	ATF_CHECK_EQ(0, tracecmp_validate_fds(&wire.msg,
	    TRACECMP_OPEN_FD_COUNT, TRACECMP_MESSAGE_REPLY));
	ATF_CHECK_EQ(-1, tracecmp_validate_fds(&wire.msg, 0,
	    TRACECMP_MESSAGE_REPLY));
	wire.msg.status = -EPERM;
	ATF_CHECK_EQ(0, tracecmp_validate_fds(&wire.msg, 0,
	    TRACECMP_MESSAGE_REPLY));
	ATF_CHECK_EQ(-1, tracecmp_validate_fds(&wire.msg, 1,
	    TRACECMP_MESSAGE_REPLY));

	wire.msg = message(TRACECMP_OP_HELLO);
	for (size_t length = 0; length < sizeof(wire.msg); length++)
		ATF_CHECK_EQ(-1, tracecmp_validate_message(&wire.msg, length,
		    TRACECMP_MESSAGE_REQUEST));
	for (uint16_t opcode = 0; opcode <= TRACECMP_OP_STATS + 1; opcode++) {
		wire.msg.opcode = opcode;
		if (opcode >= TRACECMP_OP_HELLO &&
		    opcode <= TRACECMP_OP_STATS)
			ATF_CHECK_EQ(0, tracecmp_validate_message(&wire.msg,
			    sizeof(wire.msg), TRACECMP_MESSAGE_REQUEST));
		else
			ATF_CHECK_EQ(-1, tracecmp_validate_message(&wire.msg,
			    sizeof(wire.msg), TRACECMP_MESSAGE_REQUEST));
	}
}

ATF_TC(api);
ATF_TC_HEAD(api, tc)
{
	atf_tc_set_md_var(tc, "descr", "TraceCmp public API validates arguments");
}
ATF_TC_BODY(api, tc)
{
	ATF_CHECK_ERRNO(EINVAL, tracecmp_open(NULL) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, validation);
	ATF_TP_ADD_TC(tp, api);
	return (atf_no_error());
}
