/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "logcmp.h"

union test_buffer {
	max_align_t align;
	uint8_t bytes[LOGCMP_MAX_MESSAGE];
};

static struct logcmp_msg *
message(union test_buffer *buffer, uint16_t opcode)
{
	struct logcmp_msg *msg;

	memset(buffer, 0, sizeof(*buffer));
	msg = (void *)buffer;
	msg->magic = LOGCMP_MAGIC;
	msg->version = LOGCMP_ABI_VERSION;
	msg->opcode = opcode;
	return (msg);
}

ATF_TC(abi);
ATF_TC_HEAD(abi, tc)
{
	atf_tc_set_md_var(tc, "descr", "wire ABI sizes and opcode values are fixed");
}
ATF_TC_BODY(abi, tc)
{
	ATF_CHECK_EQ(16, sizeof(struct logcmp_msg));
	ATF_CHECK_EQ(16, sizeof(struct logcmp_hello));
	ATF_CHECK_EQ(24, sizeof(struct logcmp_hello_reply));
	ATF_CHECK_EQ(16, sizeof(struct logcmp_attach_request));
	ATF_CHECK_EQ(24, sizeof(struct logcmp_record));
	ATF_CHECK_EQ(32, sizeof(struct logcmp_stats));
	ATF_CHECK_EQ(6, LOGCMP_OP_STATS);
}

ATF_TC(message_validation);
ATF_TC_HEAD(message_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "every opcode has exact request and reply framing");
}
ATF_TC_BODY(message_validation, tc)
{
	union test_buffer buffer;
	struct logcmp_msg *msg;
	struct logcmp_hello *hello;
	struct logcmp_hello_reply *hello_reply;
	struct logcmp_record *record;
	size_t length;

	msg = message(&buffer, LOGCMP_OP_HELLO);
	length = sizeof(*msg) + sizeof(struct logcmp_hello);
	hello = (void *)(msg + 1);
	hello->min_version = LOGCMP_ABI_VERSION;
	hello->max_version = LOGCMP_ABI_VERSION;
	hello->features = LOGCMP_FEATURE_SHM_RING;
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));
	msg = message(&buffer, LOGCMP_OP_HELLO);
	length = sizeof(*msg) + sizeof(struct logcmp_hello_reply);
	hello_reply = (void *)(msg + 1);
	hello_reply->version = LOGCMP_ABI_VERSION;
	hello_reply->features = LOGCMP_FEATURE_SHM_RING;
	hello_reply->ring_size = 4096;
	hello_reply->max_record = 512;
	hello_reply->max_text = 256;
	hello_reply->max_fields = 256;
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REPLY));
	msg = message(&buffer, LOGCMP_OP_ATTACH);
	length = sizeof(*msg) + sizeof(struct logcmp_attach_request);
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));
	ATF_CHECK_EQ(0, logcmp_validate_fds(msg, LOGCMP_RING_FDS,
	    LOGCMP_MESSAGE_REQUEST));
	ATF_CHECK_EQ(-1, logcmp_validate_fds(msg, 0,
	    LOGCMP_MESSAGE_REQUEST));
	ATF_CHECK_EQ(0, logcmp_validate_fds(msg, 0,
	    LOGCMP_MESSAGE_REPLY));
	msg = message(&buffer, LOGCMP_OP_NOTIFY);
	length = sizeof(*msg);
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_EVENT));
	ATF_CHECK_EQ(0, logcmp_validate_fds(msg, 0,
	    LOGCMP_MESSAGE_EVENT));
	msg->opcode = LOGCMP_OP_FLUSH;
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_EVENT));
	msg->opcode = LOGCMP_OP_FLUSH;
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));
	msg = message(&buffer, LOGCMP_OP_STATS);
	length = sizeof(*msg) + sizeof(struct logcmp_stats);
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REPLY));

	msg = message(&buffer, LOGCMP_OP_WRITE);
	length = sizeof(*msg) + sizeof(*record) + 3;
	record = (void *)(msg + 1);
	record->sequence = 1;
	record->severity = LOGCMP_INFO;
	record->message_length = 3;
	memcpy(record + 1, "log", 3);
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));

	msg->status = -EINVAL;
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));
	msg->status = 0;
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, length - 1,
	    LOGCMP_MESSAGE_REQUEST));
	msg->flags = 0x80000000U;
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));
	msg = message(&buffer, LOGCMP_OP_FLUSH);
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, sizeof(*msg) + 1,
	    LOGCMP_MESSAGE_REPLY));
	msg = message(&buffer, LOGCMP_OP_STATS);
	msg->status = -ENOENT;
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, sizeof(*msg),
	    LOGCMP_MESSAGE_REPLY));
	msg->status = ENOENT;
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, sizeof(*msg),
	    LOGCMP_MESSAGE_REPLY));
}

ATF_TC(record_validation);
ATF_TC_HEAD(record_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "records reject forged severity, lengths, control bytes, and trusted fields");
}
ATF_TC_BODY(record_validation, tc)
{
	union test_buffer buffer;
	struct logcmp_record *record;
	char *payload;
	size_t length;

	memset(&buffer, 0, sizeof(buffer));
	record = (void *)buffer.bytes;
	payload = (void *)(record + 1);
	record->sequence = 7;
	record->severity = LOGCMP_WARNING;
	record->message_length = 5;
	record->fields_length = 9;
	memcpy(payload, "helloKEY=value", 14);
	length = sizeof(*record) + 14;
	ATF_CHECK_EQ(0, logcmp_validate_record(record, length));
	record->severity = LOGCMP_DEBUG + 1;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	record->severity = LOGCMP_INFO;
	payload[1] = '\0';
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	payload[1] = 'e';
	memcpy(payload + 5, "_PID=forged", 11);
	record->fields_length = 11;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record,
	    sizeof(*record) + 16));

	memcpy(payload + 5, "lower=value", 11);
	ATF_CHECK_EQ(-1, logcmp_validate_record(record,
	    sizeof(*record) + 16));
	memcpy(payload + 5, "KEY=value\nNEXT=two", 18);
	record->fields_length = 18;
	ATF_CHECK_EQ(0, logcmp_validate_record(record,
	    sizeof(*record) + 23));
	payload[5 + 9] = '\n';
	record->fields_length = 10;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record,
	    sizeof(*record) + 15));
	memcpy(payload + 5, "KEY=\177", 5);
	record->fields_length = 5;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record,
	    sizeof(*record) + 10));
	record->fields_length = 0;
	record->message_length = 5;
	memcpy(payload, "bad\nx", 5);
	ATF_CHECK_EQ(-1, logcmp_validate_record(record,
	    sizeof(*record) + 5));
}

ATF_TC(api_arguments);
ATF_TC_HEAD(api_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr", "public calls reject invalid arguments");
}
ATF_TC_BODY(api_arguments, tc)
{
	struct logcmp_stats stats;

	errno = 0;
	ATF_CHECK_EQ(-1, logcmp_client_open(NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, logcmp_log(NULL, LOGCMP_INFO, "x", NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, logcmp_flush(NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, logcmp_stats(NULL, &stats));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, message_validation);
	ATF_TP_ADD_TC(tp, record_validation);
	ATF_TP_ADD_TC(tp, api_arguments);
	return (atf_no_error());
}
