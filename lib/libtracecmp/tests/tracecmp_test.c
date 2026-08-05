/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tracecmp.h"
#include "tracecmp_server.h"

void tracecmp_test_calculate_sizes(uint64_t, uint32_t, uint64_t *, uint64_t *);

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

ATF_TC(tuning);
ATF_TC_HEAD(tuning, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "TraceCmp tuning scales with RAM and CPUs while remaining bounded");
}
ATF_TC_BODY(tuning, tc)
{
	const uint64_t mib = UINT64_C(1024) * 1024;
	const uint64_t gib = mib * 1024;
	uint64_t buffer, dynamic;

	tracecmp_test_calculate_sizes(512 * gib, 256, &buffer, &dynamic);
	ATF_CHECK_EQ(8 * mib, buffer);
	ATF_CHECK_EQ(64 * mib, dynamic);
	tracecmp_test_calculate_sizes(16 * gib, 8, &buffer, &dynamic);
	ATF_CHECK_EQ(8 * mib, buffer);
	ATF_CHECK_EQ(2 * mib, dynamic);
	tracecmp_test_calculate_sizes(gib, 64, &buffer, &dynamic);
	ATF_CHECK_EQ(UINT64_C(64) * 1024, buffer);
	ATF_CHECK_EQ(4 * mib, dynamic);
	tracecmp_test_calculate_sizes(16 * mib, 256, &buffer, &dynamic);
	ATF_CHECK_EQ(UINT64_C(64) * 1024, buffer);
	ATF_CHECK_EQ(4 * mib, dynamic);
	tracecmp_test_calculate_sizes(UINT64_C(1024) * gib, 1, &buffer,
	    &dynamic);
	ATF_CHECK_EQ(32 * mib, buffer);
	ATF_CHECK_EQ(64 * mib, dynamic);
	tracecmp_test_calculate_sizes(0, 0, &buffer, &dynamic);
	ATF_CHECK_EQ(4 * mib, buffer);
	ATF_CHECK_EQ(4 * mib, dynamic);
}
ATF_TC_BODY(api, tc)
{
	dtrace_hdl_t *dtp;
	int dterr, fd[2];

	ATF_CHECK_ERRNO(EINVAL, tracecmp_open(NULL) == -1);
	dterr = 0;
	ATF_CHECK(tracecmp_dtrace_open(~DTRACE_O_MASK, &dterr) == NULL);
	ATF_CHECK_EQ(EINVAL, dterr);

	ATF_REQUIRE_EQ(0, pipe(fd));
	dterr = 0;
	dtp = dtrace_fdopen(fd[0], DTRACE_VERSION, 0, &dterr);
	ATF_CHECK(dtp == NULL);
	ATF_CHECK(fcntl(fd[0], F_GETFD) != -1);
	ATF_CHECK_EQ(0, close(fd[0]));
	ATF_CHECK_EQ(0, close(fd[1]));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, validation);
	ATF_TP_ADD_TC(tp, api);
	ATF_TP_ADD_TC(tp, tuning);
	return (atf_no_error());
}
