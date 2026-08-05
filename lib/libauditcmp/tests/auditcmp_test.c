/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "auditcmp.h"
#include "auditcmp_server.h"

union buffer {
	max_align_t align;
	uint8_t bytes[AUDITCMP_MAX_MESSAGE];
};

static struct auditcmp_msg *
message(union buffer *buffer, uint16_t opcode)
{
	struct auditcmp_msg *msg;

	memset(buffer, 0, sizeof(*buffer));
	msg = (void *)buffer->bytes;
	ATF_REQUIRE_EQ(0, auditcmp_message_init(msg, opcode, 0));
	return (msg);
}

ATF_TC_WITHOUT_HEAD(abi);
ATF_TC_BODY(abi, tc)
{

	ATF_CHECK_EQ(16, sizeof(struct auditcmp_msg));
	ATF_CHECK_EQ(140, sizeof(struct auditcmp_submit_request));
	ATF_CHECK_EQ(32, sizeof(struct auditcmp_stats));
}

ATF_TC_WITHOUT_HEAD(requests);
ATF_TC_BODY(requests, tc)
{
	union buffer buffer;
	struct auditcmp_submit_request *request;
	struct auditcmp_msg *msg;
	size_t length;

	msg = message(&buffer, AUDITCMP_OP_SUBMIT);
	request = (void *)(msg + 1);
	request->subject_length = 15;
	request->operation_length = 6;
	memcpy(request->subject, "org.test.client", 15);
	memcpy(request->operation, "create", 6);
	length = sizeof(*msg) + sizeof(*request);
	ATF_CHECK_EQ(0, auditcmp_validate_message(msg, length,
	    AUDITCMP_MESSAGE_REQUEST));
	request->reserved = 1;
	ATF_CHECK_ERRNO(EPROTO, auditcmp_validate_message(msg, length,
	    AUDITCMP_MESSAGE_REQUEST) == -1);
	request->reserved = 0;
	request->subject[15] = 'x';
	ATF_CHECK_ERRNO(EPROTO, auditcmp_validate_message(msg, length,
	    AUDITCMP_MESSAGE_REQUEST) == -1);
	request->subject[15] = '\0';
	request->error = ELAST + 1;
	ATF_CHECK_ERRNO(EPROTO, auditcmp_validate_message(msg, length,
	    AUDITCMP_MESSAGE_REQUEST) == -1);
}

ATF_TC_WITHOUT_HEAD(replies);
ATF_TC_BODY(replies, tc)
{
	union buffer buffer;
	struct auditcmp_hello_reply *hello;
	struct auditcmp_msg *msg;

	msg = message(&buffer, AUDITCMP_OP_HELLO);
	hello = (void *)(msg + 1);
	hello->version = AUDITCMP_ABI_VERSION;
	ATF_CHECK_EQ(0, auditcmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*hello), AUDITCMP_MESSAGE_REPLY));
	hello->reserved[1] = 1;
	ATF_CHECK_ERRNO(EPROTO, auditcmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*hello), AUDITCMP_MESSAGE_REPLY) == -1);
	msg = message(&buffer, AUDITCMP_OP_SUBMIT);
	msg->status = -EACCES;
	ATF_CHECK_EQ(0, auditcmp_validate_message(msg, sizeof(*msg),
	    AUDITCMP_MESSAGE_REPLY));
	ATF_CHECK_ERRNO(EPROTO, auditcmp_validate_message(msg,
	    sizeof(*msg) + 1, AUDITCMP_MESSAGE_REPLY) == -1);
}

ATF_TC_WITHOUT_HEAD(descriptors_and_api);
ATF_TC_BODY(descriptors_and_api, tc)
{
	struct auditcmp_client *client;
	struct auditcmp_msg msg;
	int descriptors[2];

	ATF_REQUIRE_EQ(0, auditcmp_message_init(&msg, AUDITCMP_OP_HELLO, 0));
	ATF_CHECK_EQ(0, auditcmp_validate_fds(&msg, 0,
	    AUDITCMP_MESSAGE_REQUEST));
	ATF_CHECK_ERRNO(EPROTO, auditcmp_validate_fds(&msg, 1,
	    AUDITCMP_MESSAGE_REQUEST) == -1);
	ATF_CHECK_ERRNO(EINVAL, auditcmp_client_open(NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, auditcmp_client_prepare(NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, auditcmp_client_adopt(-1, NULL) == -1);
	ATF_REQUIRE_EQ(0, pipe(descriptors));
	ATF_CHECK(auditcmp_client_adopt(descriptors[0], &client) == -1);
	ATF_CHECK_ERRNO(EBADF, fcntl(descriptors[0], F_GETFD) == -1);
	close(descriptors[1]);
	ATF_CHECK_ERRNO(EINVAL,
	    auditcmp_submit(NULL, "org.test.client", "create", 0) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, requests);
	ATF_TP_ADD_TC(tp, replies);
	ATF_TP_ADD_TC(tp, descriptors_and_api);
	return (atf_no_error());
}
