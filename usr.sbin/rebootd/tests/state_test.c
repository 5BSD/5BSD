/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/reboot.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include <rebootctl.h>

#include "rebootd_state.h"

static struct rebootd_state_record
active_record(void)
{
	struct rebootd_state_record record;

	memset(&record, 0, sizeof(record));
	record.active = 1;
	record.next_request_id = 9;
	record.request_id = 9;
	record.requested_at_ns = 100;
	record.execute_at_ns = 200;
	record.howto = RB_REROOT;
	record.opcode = REBOOTCTL_OP_REBOOT;
	record.requester_length = 8;
	memcpy(record.requester, "org.test", 8);
	rebootd_state_seal(&record);
	return (record);
}

ATF_TC_WITHOUT_HEAD(idle_and_active_roundtrip);
ATF_TC_BODY(idle_and_active_roundtrip, tc)
{
	struct rebootd_state_record record;

	(void)tc;
	memset(&record, 0, sizeof(record));
	rebootd_state_seal(&record);
	ATF_CHECK(rebootd_state_valid(&record));
	record = active_record();
	ATF_CHECK(rebootd_state_valid(&record));
}

ATF_TC_WITHOUT_HEAD(every_byte_is_integrity_protected);
ATF_TC_BODY(every_byte_is_integrity_protected, tc)
{
	struct rebootd_state_record original, changed;
	uint8_t *bytes;
	size_t i;

	(void)tc;
	original = active_record();
	for (i = 0; i < sizeof(original); i++) {
		changed = original;
		bytes = (uint8_t *)&changed;
		bytes[i] ^= UINT8_C(0x80);
		ATF_CHECK_MSG(!rebootd_state_valid(&changed),
		    "changed byte %zu was accepted", i);
	}
}

ATF_TC_WITHOUT_HEAD(semantic_corruption_is_rejected_after_reseal);
ATF_TC_BODY(semantic_corruption_is_rejected_after_reseal, tc)
{
	struct rebootd_state_record record;

	(void)tc;
	record = active_record();
	record.active = 2;
	rebootd_state_seal(&record);
	ATF_CHECK(!rebootd_state_valid(&record));
	record = active_record();
	record.execute_at_ns = record.requested_at_ns - 1;
	rebootd_state_seal(&record);
	ATF_CHECK(!rebootd_state_valid(&record));
	record = active_record();
	record.opcode = REBOOTCTL_OP_CANCEL;
	rebootd_state_seal(&record);
	ATF_CHECK(!rebootd_state_valid(&record));
	record = active_record();
	record.requester[record.requester_length + 1] = 'x';
	rebootd_state_seal(&record);
	ATF_CHECK(!rebootd_state_valid(&record));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, idle_and_active_roundtrip);
	ATF_TP_ADD_TC(tp, every_byte_is_integrity_protected);
	ATF_TP_ADD_TC(tp, semantic_corruption_is_rejected_after_reseal);
	return (atf_no_error());
}
