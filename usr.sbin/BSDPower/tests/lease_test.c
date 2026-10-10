/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <powercmp_protocol.h>
#include <service_runtime.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Drive the real handler without any ACPI descriptor or privileged transport.
 */
struct channel_message {
	size_t length;
	unsigned char data[POWERCMP_MAX_MESSAGE];
};
static struct powercmp_msg captured_reply;
static struct powercmp_body reply_body;
static bool send_failure;
static const void *
message_data(const struct channel_message *m)
{
	return (m->data);
}
static size_t
message_length(const struct channel_message *m)
{
	return (m->length);
}
static size_t
message_fds(const struct channel_message *m)
{
	(void)m;
	return (0);
}
static void
message_free(struct channel_message *m)
{
	free(m);
}
static int
send_reply(struct channel_message *m, const struct channel_outgoing *o)
{
	(void)m;
	if (send_failure)
		return (errno = EPIPE, -1);
	memcpy(&captured_reply, o->data, sizeof(captured_reply));
	if (o->length > sizeof(captured_reply))
		memcpy(&reply_body, (const char *)o->data + sizeof(captured_reply),
		    sizeof(reply_body));
	return (0);
}
#define channel_message_data	 message_data
#define channel_message_length	 message_length
#define channel_message_fd_count message_fds
#define channel_message_free	 message_free
#define channel_send_reply	 send_reply
#define BSDPOWER_TESTING
#include "../BSDPower.c"
static int
request(struct session *s, uint32_t op)
{
	struct channel_message *m = calloc(1, sizeof(*m));
	struct powercmp_msg *header = (void *)m->data;
	struct powercmp_body *body = (void *)(header + 1);
	header->magic = POWERCMP_MAGIC;
	header->opcode = op;
	m->length = sizeof(*header);
	if (op == POWERCMP_OP_SUSPEND) {
		m->length += sizeof(*body);
		body->state = 3;
	}
	captured_reply.status = -999;
	handle_request(NULL, m, s);
	return (-captured_reply.status);
}
ATF_TC_WITHOUT_HEAD(lease_blocks_suspend_until_owner_disconnect);
ATF_TC_BODY(lease_blocks_suspend_until_owner_disconnect, tc)
{
	struct powercmp_config config = { 0 };
	struct session a = { .label = "inhibitor",
		.owner = 1,
		.config = &config };
	struct session b = { .label = "controller",
		.owner = 2,
		.config = &config };
	config.nclients = 2;
	strlcpy(config.clients[0].label, "inhibitor",
	    sizeof(config.clients[0].label));
	config.clients[0].may_inhibit = true;
	strlcpy(config.clients[1].label, "controller",
	    sizeof(config.clients[1].label));
	config.clients[1].may_suspend = true;
	ATF_REQUIRE_EQ(0, service_lease_set_create(2, &g_leases));
	ATF_CHECK_EQ(EPERM, request(&b, POWERCMP_OP_INHIBIT));
	ATF_REQUIRE_EQ(0, request(&a, POWERCMP_OP_INHIBIT));
	ATF_CHECK_EQ(EALREADY, request(&a, POWERCMP_OP_INHIBIT));
	ATF_CHECK_EQ(ENOENT, request(&b, POWERCMP_OP_UNINHIBIT));
	ATF_CHECK_EQ(0, request(&b, POWERCMP_OP_INHIBITORS));
	ATF_CHECK_EQ(1, reply_body.supported);
	ATF_CHECK_EQ(EBUSY, request(&b, POWERCMP_OP_SUSPEND));
	session_close(&a);
	ATF_CHECK_EQ(0, service_lease_count(g_leases));
	ATF_CHECK_EQ(ENODEV, request(&b, POWERCMP_OP_SUSPEND));
	service_lease_set_destroy(g_leases);
	g_leases = NULL;
}
ATF_TC_WITHOUT_HEAD(release_and_failed_reply_cleanup);
ATF_TC_BODY(release_and_failed_reply_cleanup, tc)
{
	struct powercmp_config config = { .default_inhibit = true };
	struct session s = { .label = "a", .owner = 1, .config = &config };
	ATF_REQUIRE_EQ(0, service_lease_set_create(2, &g_leases));
	ATF_REQUIRE_EQ(0, request(&s, POWERCMP_OP_INHIBIT));
	ATF_REQUIRE_EQ(0, request(&s, POWERCMP_OP_UNINHIBIT));
	ATF_CHECK_EQ(0, service_lease_count(g_leases));
	send_failure = true;
	(void)request(&s, POWERCMP_OP_INHIBIT);
	ATF_CHECK_EQ(EPIPE, s.error);
	session_close(&s);
	ATF_CHECK_EQ(0, service_lease_count(g_leases));
	service_lease_set_destroy(g_leases);
	g_leases = NULL;
	send_failure = false;
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lease_blocks_suspend_until_owner_disconnect);
	ATF_TP_ADD_TC(tp, release_and_failed_reply_cleanup);
	return (atf_no_error());
}
