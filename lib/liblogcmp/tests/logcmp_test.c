/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logcmp.h"
#include "logcmp_server.h"
#include "logcmp_wakeup.h"

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
	ATF_CHECK_EQ(104, sizeof(struct logcmp_record));
	ATF_CHECK_EQ(8, sizeof(struct logcmp_attribute_wire));
	ATF_CHECK_EQ(432, sizeof(struct logcmp_stats));
	ATF_CHECK_EQ(16, sizeof(struct logcmp_query_cursor));
	ATF_CHECK_EQ(208, sizeof(struct logcmp_query_request));
	ATF_CHECK_EQ(24, sizeof(struct logcmp_query_reply));
	ATF_CHECK_EQ(6, LOGCMP_OP_STATS);
	ATF_CHECK_EQ(8, LOGCMP_OP_QUERY);
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
	msg = message(&buffer, LOGCMP_OP_QUERY);
	length = sizeof(*msg) + sizeof(struct logcmp_query_request);
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));
	((struct logcmp_query_request *)(void *)(msg + 1))->reserved = 1;
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REQUEST));
	msg = message(&buffer, LOGCMP_OP_QUERY);
	length = sizeof(*msg) + sizeof(struct logcmp_query_reply);
	ATF_CHECK_EQ(0, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REPLY));
	((struct logcmp_query_reply *)(void *)(msg + 1))->result = 2;
	ATF_CHECK_EQ(-1, logcmp_validate_message(msg, length,
	    LOGCMP_MESSAGE_REPLY));

	msg = message(&buffer, LOGCMP_OP_WRITE);
	length = sizeof(*msg) + sizeof(*record) + 3;
	record = (void *)(msg + 1);
	record->sequence = 1;
	record->timestamp_ns = 1;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = 3;
	record->category_length = 4;
	record->message_length = 3;
	memcpy(record + 1, "svcmainlog", 10);
	length += 7;
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
	struct logcmp_attribute_wire *attribute;
	struct logcmp_record *record;
	char *payload;
	size_t length;

	memset(&buffer, 0, sizeof(buffer));
	record = (void *)buffer.bytes;
	payload = (void *)(record + 1);
	record->sequence = 7;
	record->timestamp_ns = 1;
	record->severity = LOGCMP_SEVERITY_WARN;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = 3;
	record->category_length = 4;
	record->message_length = 5;
	memcpy(payload, "svcmainhello", 12);
	length = sizeof(*record) + 12;
	ATF_CHECK_EQ(0, logcmp_validate_record(record, length));
	record->sequence = 0;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	record->sequence = 7;
	record->timestamp_ns = 0;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	record->timestamp_ns = 1;
	record->severity = 25;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	record->severity = LOGCMP_SEVERITY_INFO;
	payload[8] = '\0';
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	payload[8] = 'h';
	record->attribute_count = 1;
	record->attributes_length = sizeof(*attribute) + 3 + 8;
	attribute = (void *)(payload + 12);
	attribute->key_length = 3;
	attribute->type = LOGCMP_ATTR_UINT64;
	attribute->privacy = LOGCMP_PRIVACY_PRIVATE_HASH;
	attribute->value_length = 8;
	memcpy(attribute + 1, "uid", 3);
	memset((char *)(attribute + 1) + 3, 1, 8);
	length += record->attributes_length;
	ATF_CHECK_EQ(0, logcmp_validate_record(record, length));
	((char *)(attribute + 1))[0] = '_';
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	((char *)(attribute + 1))[0] = 'u';
	attribute->value_length = 7;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	attribute->value_length = 8;
	record->message_privacy = 0;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->kind = LOGCMP_KIND_SIGNPOST_BEGIN;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
}

ATF_TC(record_attribute_uniqueness);
ATF_TC_HEAD(record_attribute_uniqueness, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "structured records reject duplicate and malformed attribute keys");
}

ATF_TC_WITHOUT_HEAD(record_rejects_redaction_expansion);
ATF_TC_BODY(record_rejects_redaction_expansion, tc)
{
	union test_buffer buffer;
	struct logcmp_attribute_wire attribute;
	struct logcmp_record *record;
	uint8_t *cursor;
	size_t length, i;

	memset(&buffer, 0, sizeof(buffer));
	record = (void *)buffer.bytes;
	record->sequence = 1;
	record->timestamp_ns = 1;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = LOGCMP_MAX_SUBSYSTEM;
	record->category_length = LOGCMP_MAX_CATEGORY;
	record->message_length = 1700;
	record->attribute_count = LOGCMP_MAX_ATTRIBUTES;
	record->attributes_length = LOGCMP_MAX_ATTRIBUTES *
	    (sizeof(attribute) + 54 + 1);
	cursor = (void *)(record + 1);
	memset(cursor, 's', record->subsystem_length);
	cursor += record->subsystem_length;
	memset(cursor, 'c', record->category_length);
	cursor += record->category_length;
	memset(cursor, 'm', record->message_length);
	cursor += record->message_length;
	memset(&attribute, 0, sizeof(attribute));
	attribute.key_length = 54;
	attribute.type = LOGCMP_ATTR_STRING;
	attribute.privacy = LOGCMP_PRIVACY_PUBLIC;
	attribute.value_length = 1;
	for (i = 0; i < LOGCMP_MAX_ATTRIBUTES; i++) {
		char key[54];

		memset(key, 'a', sizeof(key));
		key[sizeof(key) - 2] = 'A' + i / 10;
		key[sizeof(key) - 1] = '0' + i % 10;
		memcpy(cursor, &attribute, sizeof(attribute));
		cursor += sizeof(attribute);
		memcpy(cursor, key, sizeof(key));
		cursor += sizeof(key);
		*cursor++ = 'x';
	}
	length = cursor - buffer.bytes;
	ATF_REQUIRE(length <= LOGCMP_MAX_RECORD);
	ATF_REQUIRE(record->attributes_length <= LOGCMP_MAX_FIELDS);
	ATF_CHECK_EQ(0, logcmp_validate_record(record, length));
	cursor = (uint8_t *)(record + 1) + record->subsystem_length +
	    record->category_length + record->message_length;
	for (i = 0; i < LOGCMP_MAX_ATTRIBUTES; i++) {
		((struct logcmp_attribute_wire *)(void *)cursor)->privacy =
		    LOGCMP_PRIVACY_PRIVATE_HASH;
		cursor += sizeof(attribute) + 54 + 1;
	}
	ATF_CHECK_ERRNO(EPROTO,
	    logcmp_validate_record(record, length) == -1);
}
ATF_TC_BODY(record_attribute_uniqueness, tc)
{
	union test_buffer buffer;
	struct logcmp_attribute_wire *first, *second;
	struct logcmp_record *record;
	uint8_t *cursor;
	size_t length;

	memset(&buffer, 0, sizeof(buffer));
	record = (void *)buffer.bytes;
	record->sequence = 1;
	record->timestamp_ns = 1;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = 3;
	record->category_length = 4;
	record->message_length = 1;
	record->attribute_count = 2;
	record->attributes_length = 2 * (sizeof(*first) + 3 + 1);
	cursor = (void *)(record + 1);
	memcpy(cursor, "svcmainx", 8);
	cursor += 8;
	first = (void *)cursor;
	first->key_length = 3;
	first->type = LOGCMP_ATTR_BOOL;
	first->privacy = LOGCMP_PRIVACY_PUBLIC;
	first->value_length = 1;
	memcpy(first + 1, "key", 3);
	*((uint8_t *)(first + 1) + 3) = 1;
	cursor += sizeof(*first) + 4;
	second = (void *)cursor;
	*second = *first;
	memcpy(second + 1, "key", 3);
	*((uint8_t *)(second + 1) + 3) = 0;
	length = sizeof(*record) + 8 + record->attributes_length;
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
	memcpy(second + 1, "kez", 3);
	ATF_CHECK_EQ(0, logcmp_validate_record(record, length));
	((uint8_t *)(second + 1))[2] = '-';
	ATF_CHECK_EQ(-1, logcmp_validate_record(record, length));
}

ATF_TC(api_arguments);
ATF_TC_HEAD(api_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr", "public calls reject invalid arguments");
}

ATF_TC(wakeup);
ATF_TC_HEAD(wakeup, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "edge wakeups coalesce, drain nonblockingly, reject wrong descriptors, and survive peer death");
}
ATF_TC_BODY(wakeup, tc)
{
	uint8_t byte;
	int pipefds[2], stream[2], wake[2];

	ATF_CHECK_ERRNO(EINVAL, logcmp_wakeup_create(NULL) == -1);
	ATF_REQUIRE_EQ(0, logcmp_wakeup_create(wake));
	ATF_CHECK_EQ(0,
	    logcmp_wakeup_validate_consumer(wake[LOGCMP_WAKE_CONSUMER]));
	ATF_CHECK_EQ(0,
	    logcmp_wakeup_signal(wake[LOGCMP_WAKE_PRODUCER], false));
	ATF_CHECK_ERRNO(EAGAIN,
	    read(wake[LOGCMP_WAKE_CONSUMER], &byte, sizeof(byte)) == -1);
	ATF_REQUIRE_EQ(0,
	    logcmp_wakeup_signal(wake[LOGCMP_WAKE_PRODUCER], true));
	ATF_REQUIRE_EQ(0,
	    logcmp_wakeup_signal(wake[LOGCMP_WAKE_PRODUCER], true));
	ATF_CHECK_EQ(0, logcmp_wakeup_drain(wake[LOGCMP_WAKE_CONSUMER]));
	ATF_CHECK_ERRNO(EAGAIN,
	    read(wake[LOGCMP_WAKE_CONSUMER], &byte, sizeof(byte)) == -1);
	close(wake[LOGCMP_WAKE_CONSUMER]);
	ATF_CHECK_EQ(-1,
	    logcmp_wakeup_signal(wake[LOGCMP_WAKE_PRODUCER], true));
	close(wake[LOGCMP_WAKE_PRODUCER]);

	ATF_REQUIRE_EQ(0, pipe2(pipefds, O_CLOEXEC | O_NONBLOCK));
	ATF_CHECK_ERRNO(EPROTOTYPE,
	    logcmp_wakeup_validate_consumer(pipefds[0]) == -1);
	close(pipefds[0]);
	close(pipefds[1]);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX,
	    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, stream));
	ATF_CHECK_ERRNO(EPROTOTYPE,
	    logcmp_wakeup_validate_consumer(stream[0]) == -1);
	close(stream[0]);
	close(stream[1]);
}
ATF_TC_BODY(api_arguments, tc)
{
	struct logcmp_stats stats;
	struct logcmp_emit_options options;

	errno = 0;
	ATF_CHECK_EQ(-1, logcmp_client_open(NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "x";
	ATF_CHECK_EQ(-1, logcmp_emit(NULL, &options));
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
	ATF_TP_ADD_TC(tp, record_attribute_uniqueness);
	ATF_TP_ADD_TC(tp, record_rejects_redaction_expansion);
	ATF_TP_ADD_TC(tp, api_arguments);
	ATF_TP_ADD_TC(tp, wakeup);
	return (atf_no_error());
}
