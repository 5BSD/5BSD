/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "kldmgr.h"
#include "kldmgr_server.h"

static struct kldmgr_msg
message(uint16_t opcode, int32_t status)
{
	struct kldmgr_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.magic = KLDMGR_MAGIC;
	msg.version = KLDMGR_ABI_VERSION;
	msg.opcode = opcode;
	msg.status = status;
	return (msg);
}

ATF_TC_WITHOUT_HEAD(abi);
ATF_TC_BODY(abi, tc)
{

	ATF_CHECK_EQ(16, sizeof(struct kldmgr_msg));
	ATF_CHECK_EQ(128, sizeof(struct kldmgr_module_request));
	ATF_CHECK_EQ(8, sizeof(struct kldmgr_id_reply));
}

ATF_TC_WITHOUT_HEAD(request_validation);
ATF_TC_BODY(request_validation, tc)
{
	struct {
		struct kldmgr_msg msg;
		struct kldmgr_module_request request;
	} wire;

	memset(&wire, 0, sizeof(wire));
	wire.msg = message(KLDMGR_OP_LOAD, 0);
	strlcpy(wire.request.name, "if_bridge", sizeof(wire.request.name));
	ATF_CHECK_EQ(0, kldmgr_validate_request(&wire.msg, sizeof(wire)));
	wire.request.name[sizeof(wire.request.name) - 1] = 'x';
	memset(wire.request.name, 'x', sizeof(wire.request.name));
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_request(&wire.msg, sizeof(wire)) == -1);
	wire.msg = message(KLDMGR_OP_LIST, 0);
	ATF_CHECK_EQ(0, kldmgr_validate_request(&wire.msg, sizeof(wire.msg)));
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_request(&wire.msg, sizeof(wire)) == -1);
}

ATF_TC_WITHOUT_HEAD(reply_validation);
ATF_TC_BODY(reply_validation, tc)
{
	uint8_t storage[sizeof(struct kldmgr_msg) +
	    sizeof(struct kldmgr_list_reply) +
	    2 * sizeof(struct kldmgr_list_entry)];
	struct kldmgr_msg *msg;
	struct kldmgr_list_reply *reply;

	memset(storage, 0, sizeof(storage));
	msg = (void *)storage;
	*msg = message(KLDMGR_OP_LIST, 0);
	reply = (void *)(msg + 1);
	reply->count = 2;
	reply->entries[0].id = 1;
	strlcpy(reply->entries[0].name, "if_bridge",
	    sizeof(reply->entries[0].name));
	reply->entries[1].id = 2;
	strlcpy(reply->entries[1].name, "pf", sizeof(reply->entries[1].name));
	ATF_CHECK_EQ(0, kldmgr_validate_reply(msg, sizeof(storage)));
	memset(reply->entries[1].name, 'x', sizeof(reply->entries[1].name));
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_reply(msg, sizeof(storage)) == -1);
	strlcpy(reply->entries[1].name, "pf", sizeof(reply->entries[1].name));
	reply->entries[1].id = -1;
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_reply(msg, sizeof(storage)) == -1);
	reply->entries[1].id = 2;
	reply->count = KLDMGR_LIST_MAX + 1;
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_reply(msg, sizeof(storage)) == -1);
	*msg = message(KLDMGR_OP_LIST, -EACCES);
	ATF_CHECK_EQ(0, kldmgr_validate_reply(msg, sizeof(*msg)));
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_reply(msg, sizeof(storage)) == -1);
}

ATF_TC_WITHOUT_HEAD(id_reply_validation);
ATF_TC_BODY(id_reply_validation, tc)
{
	struct {
		struct kldmgr_msg msg;
		struct kldmgr_id_reply id;
	} wire;

	memset(&wire, 0, sizeof(wire));
	wire.msg = message(KLDMGR_OP_LOAD, 0);
	wire.id.id = 12;
	ATF_CHECK_EQ(0, kldmgr_validate_reply(&wire.msg, sizeof(wire)));
	wire.id.reserved = 1;
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_reply(&wire.msg, sizeof(wire)) == -1);
	wire.id.reserved = 0;
	wire.id.id = -1;
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_reply(&wire.msg, sizeof(wire)) == -1);
}

ATF_TC_WITHOUT_HEAD(header_boundaries);
ATF_TC_BODY(header_boundaries, tc)
{
	struct kldmgr_msg msg;
	size_t length;

	msg = message(KLDMGR_OP_LIST, 0);
	for (length = 0; length < sizeof(msg); length++)
		ATF_CHECK_ERRNO(EPROTO,
		    kldmgr_validate_request(&msg, length) == -1);
	msg.magic ^= 1;
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_request(&msg, sizeof(msg)) == -1);
	msg = message(KLDMGR_OP_LIST, 0);
	msg.version++;
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_request(&msg, sizeof(msg)) == -1);
	msg = message(KLDMGR_OP_LIST, 0);
	msg.flags = 1;
	ATF_CHECK_ERRNO(EPROTO,
	    kldmgr_validate_request(&msg, sizeof(msg)) == -1);
}

ATF_TC_WITHOUT_HEAD(api_misuse);
ATF_TC_BODY(api_misuse, tc)
{

	ATF_CHECK_ERRNO(EINVAL, kldmgr_client_open(NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, kldmgr_load(NULL, "x", NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, kldmgr_list(NULL, NULL, 0, NULL) == -1);
	kldmgr_client_close(NULL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, request_validation);
	ATF_TP_ADD_TC(tp, reply_validation);
	ATF_TP_ADD_TC(tp, id_reply_validation);
	ATF_TP_ADD_TC(tp, header_boundaries);
	ATF_TP_ADD_TC(tp, api_misuse);
	return (atf_no_error());
}
