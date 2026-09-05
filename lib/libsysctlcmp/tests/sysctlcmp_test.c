/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "sysctlcmp.h"
#include "sysctlcmp_server.h"

union buffer {
	max_align_t align;
	uint8_t bytes[SYSCTLCMP_MAX_MESSAGE];
};

/* Build a well-formed GET request for "name" into buf; return its length. */
static size_t
build_get(union buffer *buf, const char *name)
{
	struct sysctlcmp_msg *msg;
	struct sysctlcmp_body *body;
	size_t name_len;

	name_len = strlen(name) + 1;
	memset(buf, 0, sizeof(*buf));
	msg = (void *)buf->bytes;
	ATF_REQUIRE_EQ(0, sysctlcmp_message_init(msg, SYSCTLCMP_OP_GET, 0));
	body = (void *)(msg + 1);
	body->name_length = (uint16_t)name_len;
	body->value_length = 0;
	memcpy(body + 1, name, name_len);
	return (sizeof(*msg) + sizeof(*body) + name_len);
}

ATF_TC_WITHOUT_HEAD(abi);
ATF_TC_BODY(abi, tc)
{

	ATF_CHECK_EQ(16, sizeof(struct sysctlcmp_msg));
	ATF_CHECK_EQ(8, sizeof(struct sysctlcmp_body));
}

ATF_TC_WITHOUT_HEAD(message_init);
ATF_TC_BODY(message_init, tc)
{
	struct sysctlcmp_msg msg;

	ATF_REQUIRE_EQ(0, sysctlcmp_message_init(&msg, SYSCTLCMP_OP_GET, 0));
	ATF_CHECK_EQ(SYSCTLCMP_MAGIC, msg.magic);
	ATF_CHECK_EQ(SYSCTLCMP_ABI_VERSION, msg.version);
	ATF_CHECK_EQ(SYSCTLCMP_OP_GET, msg.opcode);
	/* Bad opcode and nonzero flags are rejected. */
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_message_init(&msg, 0, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_message_init(&msg,
	    SYSCTLCMP_OP_GET, 1) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_message_init(NULL,
	    SYSCTLCMP_OP_GET, 0) == -1);
}

ATF_TC_WITHOUT_HEAD(validate_request);
ATF_TC_BODY(validate_request, tc)
{
	union buffer buf;
	struct sysctlcmp_body *body;
	size_t len;

	len = build_get(&buf, "kern.ostype");
	ATF_CHECK_EQ(0, sysctlcmp_validate_message((void *)buf.bytes, len,
	    SYSCTLCMP_MESSAGE_REQUEST));

	/* Truncated below header+body is rejected. */
	ATF_CHECK_ERRNO(EPROTO, sysctlcmp_validate_message((void *)buf.bytes,
	    sizeof(struct sysctlcmp_msg), SYSCTLCMP_MESSAGE_REQUEST) == -1);

	/* Inconsistent name_length vs. total length is rejected. */
	body = (void *)(buf.bytes + sizeof(struct sysctlcmp_msg));
	body->name_length = (uint16_t)(body->name_length + 1);
	ATF_CHECK_ERRNO(EPROTO, sysctlcmp_validate_message((void *)buf.bytes,
	    len, SYSCTLCMP_MESSAGE_REQUEST) == -1);

	/* Oversized value_length is rejected. */
	len = build_get(&buf, "kern.ostype");
	body = (void *)(buf.bytes + sizeof(struct sysctlcmp_msg));
	body->value_length = SYSCTLCMP_MAX_VALUE + 1;
	ATF_CHECK_ERRNO(EPROTO, sysctlcmp_validate_message((void *)buf.bytes,
	    len, SYSCTLCMP_MESSAGE_REQUEST) == -1);
}

ATF_TC_WITHOUT_HEAD(validate_reply);
ATF_TC_BODY(validate_reply, tc)
{
	union buffer req, rep;
	struct sysctlcmp_msg *reply;
	size_t rlen;

	(void)build_get(&req, "kern.ostype");
	reply = (void *)rep.bytes;
	ATF_REQUIRE_EQ(0, sysctlcmp_message_init_reply(reply,
	    (void *)req.bytes, 0));
	/* A rejected reply carries only the header. */
	memset(&rep, 0, sizeof(rep));
	ATF_REQUIRE_EQ(0, sysctlcmp_message_init_reply(reply,
	    (void *)req.bytes, -EPERM));
	ATF_CHECK_EQ(0, sysctlcmp_validate_message(reply,
	    sizeof(*reply), SYSCTLCMP_MESSAGE_REPLY));
	rlen = sizeof(*reply);
	(void)rlen;
	/* Positive status is invalid. */
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_message_init_reply(reply,
	    (void *)req.bytes, 1) == -1);
}

ATF_TC_WITHOUT_HEAD(client_args);
ATF_TC_BODY(client_args, tc)
{
	size_t len = 0;

	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_client_open(NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_get(NULL, "kern.ostype", NULL,
	    &len) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_set(NULL, "kern.ostype", NULL,
	    0) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, message_init);
	ATF_TP_ADD_TC(tp, validate_request);
	ATF_TP_ADD_TC(tp, validate_reply);
	ATF_TP_ADD_TC(tp, client_args);
	return (atf_no_error());
}
