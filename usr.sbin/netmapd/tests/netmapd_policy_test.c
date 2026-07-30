#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "netmapd_policy.h"

union message_buffer {
	max_align_t align;
	struct {
		struct netmap_bearer_msg message;
		uint8_t payload[NETMAP_BEARER_MAX_MESSAGE -
		    sizeof(struct netmap_bearer_msg)];
	} wire;
};

static struct netmap_bearer_msg *
message(union message_buffer *buffer, uint16_t opcode, bool reply,
    size_t payload)
{
	struct netmap_bearer_msg *msg;

	memset(buffer, 0, sizeof(*buffer));
	msg = &buffer->wire.message;
	msg->magic = NETMAP_BEARER_MAGIC;
	msg->version = NETMAP_BEARER_VERSION;
	msg->opcode = opcode;
	msg->flags = reply ? NETMAP_BEARER_MSG_F_REPLY : 0;
	msg->length = sizeof(*msg) + payload;
	msg->request_id = 42;
	return (msg);
}

static struct netmap_bearer_create
valid_create(void)
{
	struct netmap_bearer_create request;

	memset(&request, 0, sizeof(request));
	request.type = NETMAP_BEARER_VALE;
	request.queue_count = 1;
	request.slots = 1024;
	request.flags = NETMAP_BEARER_F_RX | NETMAP_BEARER_F_TX;
	strlcpy(request.interface, "vale0:cmp0", sizeof(request.interface));
	return (request);
}

ATF_TC(message_shapes);
ATF_TC_HEAD(message_shapes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "netmap bearer requests, replies, errors, and fd counts are exact");
}
ATF_TC_BODY(message_shapes, tc)
{
	union message_buffer buffer;
	struct netmap_bearer_msg *msg;

	msg = message(&buffer, NETMAP_BEARER_OP_CREATE, false,
	    sizeof(struct netmap_bearer_create));
	ATF_CHECK_EQ(0, netmapd_validate_message(msg, msg->length, 0));
	ATF_CHECK_EQ(-1, netmapd_validate_message(msg, msg->length, 1));
	ATF_CHECK_EQ(EPROTO, errno);
	msg = message(&buffer, NETMAP_BEARER_OP_CREATE, true,
	    sizeof(struct netmap_bearer_reply));
	ATF_CHECK_EQ(0, netmapd_validate_message(msg, msg->length, 1));
	ATF_CHECK_EQ(-1, netmapd_validate_message(msg, msg->length, 0));
	msg = message(&buffer, NETMAP_BEARER_OP_CREATE, true, 0);
	msg->status = -EPERM;
	ATF_CHECK_EQ(0, netmapd_validate_message(msg, msg->length, 0));
	msg->length++;
	ATF_CHECK_EQ(-1, netmapd_validate_message(msg, msg->length, 0));
}

ATF_TC(header_matrix);
ATF_TC_HEAD(header_matrix, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "every malformed netmap bearer header field fails closed");
}
ATF_TC_BODY(header_matrix, tc)
{
	union message_buffer buffer;
	struct netmap_bearer_msg *msg;

#define	REJECT(field, value) do {					\
	msg = message(&buffer, NETMAP_BEARER_OP_HELLO, false, 0);	\
	msg->field = (value);						\
	ATF_CHECK_EQ(-1, netmapd_validate_message(msg, msg->length, 0));\
	ATF_CHECK_EQ(EPROTO, errno);					\
} while (0)
	REJECT(magic, 0);
	REJECT(version, 0);
	REJECT(opcode, 0);
	REJECT(opcode, NETMAP_BEARER_OP_REPLACE_POLICY + 1);
	REJECT(flags, 0x80000000U);
	REJECT(status, -EPERM);
	REJECT(reserved, 1);
	REJECT(length, sizeof(*msg) - 1);
#undef REJECT
	ATF_CHECK_EQ(-1, netmapd_validate_message(NULL, 0, 0));
	ATF_CHECK_EQ(EPROTO, errno);
}

ATF_TC(vale_allowlist);
ATF_TC_HEAD(vale_allowlist, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "only canonical VALE names and supported sizing are accepted");
}
ATF_TC_BODY(vale_allowlist, tc)
{
	struct netmap_bearer_create request;

	request = valid_create();
	ATF_CHECK_EQ(0, netmapd_validate_create(&request));
	request.slots = 65537;
	ATF_CHECK_EQ(-1, netmapd_validate_create(&request));
	request = valid_create();
	request.buffer_size = 2048;
	ATF_CHECK_EQ(-1, netmapd_validate_create(&request));
	request = valid_create();
	request.queue_count = 2;
	ATF_CHECK_EQ(-1, netmapd_validate_create(&request));
}

ATF_TC(physical_denied);
ATF_TC_HEAD(physical_denied, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "host and physical-queue bearer types are denied");
}
ATF_TC_BODY(physical_denied, tc)
{
	struct netmap_bearer_create request;

	request = valid_create();
	request.type = NETMAP_BEARER_HOST;
	strlcpy(request.interface, "em0", sizeof(request.interface));
	ATF_CHECK_EQ(-1, netmapd_validate_create(&request));
	ATF_CHECK_EQ(EPERM, errno);
	request.type = NETMAP_BEARER_PHYSICAL_QUEUE;
	request.flags |= NETMAP_BEARER_F_TRUSTED_PHYSICAL;
	ATF_CHECK_EQ(-1, netmapd_validate_create(&request));
	ATF_CHECK_EQ(EPERM, errno);
}

ATF_TC(option_injection_denied);
ATF_TC_HEAD(option_injection_denied, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "netmap modes, options, pipes, and path syntax cannot be injected");
}
ATF_TC_BODY(option_injection_denied, tc)
{
	struct netmap_bearer_create request;
	const char *bad[] = {
	    "vale0:cmp0@conf:slots=1",
	    "vale0:cmp0/R",
	    "vale0:cmp0{pipe",
	    "vale0:cmp0^",
	    "netmap:em0",
	    "vale0/../em0",
	};
	size_t i;

	for (i = 0; i < nitems(bad); i++) {
		request = valid_create();
		strlcpy(request.interface, bad[i], sizeof(request.interface));
		ATF_CHECK_EQ_MSG(-1, netmapd_validate_create(&request),
		    "accepted %s", bad[i]);
	}
}

ATF_TC(flags);
ATF_TC_HEAD(flags, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "direction is mandatory and unknown privilege flags fail closed");
}
ATF_TC_BODY(flags, tc)
{
	struct netmap_bearer_create request;

	request = valid_create();
	request.flags = 0;
	ATF_CHECK_EQ(-1, netmapd_validate_create(&request));
	request = valid_create();
	request.flags |= 0x100U;
	ATF_CHECK_EQ(-1, netmapd_validate_create(&request));
	request = valid_create();
	request.flags = NETMAP_BEARER_F_RX;
	ATF_CHECK_EQ(0, netmapd_validate_create(&request));
	request.flags = NETMAP_BEARER_F_TX;
	ATF_CHECK_EQ(0, netmapd_validate_create(&request));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, message_shapes);
	ATF_TP_ADD_TC(tp, header_matrix);
	ATF_TP_ADD_TC(tp, vale_allowlist);
	ATF_TP_ADD_TC(tp, physical_denied);
	ATF_TP_ADD_TC(tp, option_injection_denied);
	ATF_TP_ADD_TC(tp, flags);
	return (atf_no_error());
}
