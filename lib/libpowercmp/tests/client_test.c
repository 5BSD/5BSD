/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <libservice.h>
#include <powercmp_protocol.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
static int calls, closes, transport_error, reply_error;
static bool malformed;
static int
fake_call(struct service_session *s, const struct service_message *out,
    struct service_reply *in, const struct service_call_options *options)
{
	const struct powercmp_msg *request = out->data;
	struct powercmp_msg *reply = in->data;
	(void)s;
	(void)options;
	calls++;
	if (transport_error)
		return (errno = transport_error, -1);
	memset(reply, 0, in->capacity);
	reply->magic = POWERCMP_MAGIC;
	reply->opcode = request->opcode;
	reply->status = -reply_error;
	reply->flags = malformed ? 1 : 0;
	in->length = sizeof(*reply);
	if (!reply_error &&
	    (request->opcode == POWERCMP_OP_STATES ||
		request->opcode == POWERCMP_OP_INHIBITORS))
		in->length += sizeof(struct powercmp_body);
	return (0);
}
static void
fake_close(struct service_session *s)
{
	(void)s;
	closes++;
}
#define service_session_call  fake_call
#define service_session_close fake_close
#include "../powercmp.c"
ATF_TC_WITHOUT_HEAD(ambiguous_acquisition_closes_once);
ATF_TC_BODY(ambiguous_acquisition_closes_once, tc)
{
	struct powercmp_client client = { .session = (void *)1,
		.owner = getpid() };
	transport_error = ETIMEDOUT;
	ATF_CHECK_ERRNO(ETIMEDOUT, powercmp_inhibit(&client) == -1);
	ATF_CHECK_EQ(1, closes);
	ATF_CHECK(client.session == NULL);
	transport_error = 0;
	ATF_CHECK_ERRNO(ETIMEDOUT, powercmp_inhibit(&client) == -1);
	ATF_CHECK_EQ(1, calls);
	ATF_CHECK_EQ(1, closes);
}
ATF_TC_WITHOUT_HEAD(policy_error_preserves_session);
ATF_TC_BODY(policy_error_preserves_session, tc)
{
	struct powercmp_client client = { .session = (void *)1,
		.owner = getpid() };
	reply_error = EPERM;
	ATF_CHECK_ERRNO(EPERM, powercmp_inhibit(&client) == -1);
	ATF_CHECK_EQ(0, closes);
	reply_error = 0;
	ATF_CHECK_EQ(0, powercmp_inhibit(&client));
	ATF_CHECK_EQ(2, calls);
}
ATF_TC_WITHOUT_HEAD(malformed_reply_loses_lease);
ATF_TC_BODY(malformed_reply_loses_lease, tc)
{
	struct powercmp_client client = { .session = (void *)1,
		.owner = getpid() };
	uint32_t count = 99;
	ATF_REQUIRE_EQ(0, powercmp_inhibit(&client));
	malformed = true;
	ATF_CHECK_ERRNO(EPROTO, powercmp_inhibitors(&client, &count) == -1);
	ATF_CHECK_EQ(99, count);
	ATF_CHECK_EQ(1, closes);
	ATF_CHECK_ERRNO(EPROTO, powercmp_uninhibit(&client) == -1);
	ATF_CHECK_EQ(2, calls);
}
ATF_TC_WITHOUT_HEAD(fork_owner_cannot_drop_parent_lease);
ATF_TC_BODY(fork_owner_cannot_drop_parent_lease, tc)
{
	struct powercmp_client client = { .session = (void *)1,
		.owner = getpid() + 1 };
	ATF_CHECK_ERRNO(ECHILD, powercmp_uninhibit(&client) == -1);
	ATF_CHECK_EQ(0, closes);
	ATF_CHECK_EQ(0, calls);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, ambiguous_acquisition_closes_once);
	ATF_TP_ADD_TC(tp, policy_error_preserves_session);
	ATF_TP_ADD_TC(tp, malformed_reply_loses_lease);
	ATF_TP_ADD_TC(tp, fork_owner_cannot_drop_parent_lease);
	return (atf_no_error());
}
