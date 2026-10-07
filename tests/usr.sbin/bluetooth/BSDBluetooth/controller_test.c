/* SPDX-License-Identifier: BSD-2-Clause */
#define main controller_main_unused
#include "controller/controller.c"
#undef main
#include <atf-c.h>
#include <fcntl.h>

static int opens;
static int response_error, response_fd;
static void
controller_test_reply(struct channel_request *request __unused,
    struct channel_message *message, int error, void *arg __unused)
{
	const struct blued_controller_reply *reply;
	ATF_REQUIRE_EQ(0, error);
	ATF_REQUIRE(message != NULL);
	ATF_REQUIRE_EQ(sizeof(*reply), channel_message_length(message));
	reply = channel_message_data(message);
	ATF_REQUIRE_EQ(BLUED_CONTROLLER_MAGIC, reply->magic);
	response_error = reply->error;
	ATF_REQUIRE_EQ(reply->error == 0 ? 1U : 0U,
	    channel_message_fd_count(message));
	if (reply->error == 0)
		response_fd = channel_message_take_fd(message, 0);
	channel_message_free(message);
}

static void
controller_test_exchange(service_rights_t rights, int expected, bool timeout)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct controller_client server = { .rights = rights, .timer = next_timer++ };
	struct channel *client;
	struct channel_request *pending;
	struct blued_controller_request input = { .magic = BLUED_CONTROLLER_MAGIC,
	    .adapter = "ubt0hci" };
	struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(&input, sizeof(input));
	struct kevent ev, events[4];
	struct timespec wait = { .tv_nsec = 100000000 };
	int pair[2], turn, count, i;

	queue = kqueue();
	ATF_REQUIRE(queue >= 0);
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	ATF_REQUIRE_EQ(0, channel_create(pair[0], &options, &server.channel));
	options.role = CHANNEL_ROLE_CLIENT;
	ATF_REQUIRE_EQ(0, channel_create(pair[1], &options, &client));
	ATF_REQUIRE_EQ(0, channel_set_request_handler(server.channel,
	    controller_request, &server));
	EV_SET(&ev, channel_fd(server.channel), EVFILT_READ, EV_ADD, 0, 0, &server);
	ATF_REQUIRE_EQ(0, kevent(queue, &ev, 1, NULL, 0, NULL));
	controller_event(&server, &ev);
	ATF_REQUIRE(server.channel != NULL);
	if (timeout) {
		ev.filter = EVFILT_TIMER;
		controller_event(&server, &ev);
		controller_event(&server, &ev);
	} else {
		response_error = response_fd = -1;
		ATF_REQUIRE_EQ(0, channel_send_request(client, &out,
		    controller_test_reply, NULL, &pending));
		ATF_REQUIRE_EQ(0, channel_flush(client));
		for (turn = 0; turn < 20 && response_error < 0; turn++) {
			count = kevent(queue, NULL, 0, events, 4, &wait);
			ATF_REQUIRE(count >= 0);
			for (i = 0; i < count; i++)
				controller_event(&server, &events[i]);
			(void)channel_dispatch(client);
		}
		ATF_CHECK_EQ(expected, response_error);
		if (response_fd >= 0)
			close(response_fd);
	}
	channel_destroy(client);
	if (!timeout) {
		count = kevent(queue, NULL, 0, events, 4, &wait);
		ATF_REQUIRE(count >= 0);
		for (i = 0; i < count; i++)
			controller_event(&server, &events[i]);
	}
	ATF_CHECK(server.channel == NULL && server.retired);
	controller_close(&server);
	close(queue);
}
int __wrap_bt_devopen(const char *name);
int
__wrap_bt_devopen(const char *name __unused)
{
	int sv[2];
	opens++;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return (-1);
	close(sv[1]);
	return (sv[0]);
}

ATF_TC_WITHOUT_HEAD(controller_descriptor_rights);
ATF_TC_BODY(controller_descriptor_rights, tc)
{
	struct blued_controller_request r = { .magic = BLUED_CONTROLLER_MAGIC,
	    .adapter = "ubt0hci" };
	cap_rights_t rights;
	unsigned long commands[4];
	int fd;

	opens = 0;
	ATF_CHECK_EQ(-1, controller_open(0, &r));
	ATF_CHECK_EQ(0, opens);
	fd = controller_open(BLUED_CONTROLLER_OPEN, &r);
	ATF_REQUIRE_MSG(fd >= 0, "open errno=%d", errno);
	ATF_CHECK_EQ(1, opens);
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_READ, CAP_WRITE, CAP_IOCTL));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_BIND));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_CONNECT));
	ATF_CHECK_EQ(2, cap_ioctls_get(fd, commands, 4));
	ATF_CHECK((commands[0] == SIOC_HCI_RAW_NODE_INIT &&
	    commands[1] == SIOC_HCI_RAW_NODE_GET_CON_LIST) ||
	    (commands[1] == SIOC_HCI_RAW_NODE_INIT &&
	    commands[0] == SIOC_HCI_RAW_NODE_GET_CON_LIST));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(controller_authority);
ATF_TC_BODY(controller_authority, tc)
{
	struct blued_controller_request r = { .magic = BLUED_CONTROLLER_MAGIC,
	    .adapter = "ubt0hci" };
	ATF_CHECK_EQ(EACCES, controller_validate(0, &r));
	ATF_CHECK_EQ(EACCES, controller_validate(SERVICE_RIGHTS_ADMIN, &r));
	ATF_CHECK_EQ(0, controller_validate(BLUED_CONTROLLER_OPEN, &r));
	r.reserved = 1;
	ATF_CHECK_EQ(EINVAL, controller_validate(BLUED_CONTROLLER_OPEN, &r));
	r.reserved = 0;
	r.magic++;
	ATF_CHECK_EQ(EINVAL, controller_validate(BLUED_CONTROLLER_OPEN, &r));
}

ATF_TC_WITHOUT_HEAD(controller_names);
ATF_TC_BODY(controller_names, tc)
{
	struct blued_controller_request r = { .magic = BLUED_CONTROLLER_MAGIC };
	const char *invalid[] = { "", "/dev/hci", "../hci", "a:b", "x y" };
	size_t i;
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		strlcpy(r.adapter, invalid[i], sizeof(r.adapter));
		ATF_CHECK_EQ(EINVAL, controller_validate(BLUED_CONTROLLER_OPEN, &r));
	}
	memset(r.adapter, 'x', sizeof(r.adapter));
	ATF_CHECK_EQ(EINVAL, controller_validate(BLUED_CONTROLLER_OPEN, &r));
}

ATF_TC_WITHOUT_HEAD(controller_channel_exchange);
ATF_TC_BODY(controller_channel_exchange, tc)
{
	opens = 0;
	controller_test_exchange(0, EACCES, false);
	ATF_CHECK_EQ(0, opens);
	controller_test_exchange(BLUED_CONTROLLER_OPEN, 0, false);
	ATF_CHECK_EQ(1, opens);
}

ATF_TC_WITHOUT_HEAD(controller_pending_cleanup);
ATF_TC_BODY(controller_pending_cleanup, tc)
{
	opens = 0;
	controller_test_exchange(BLUED_CONTROLLER_OPEN, 0, true);
	ATF_CHECK_EQ(0, opens);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, controller_authority);
	ATF_TP_ADD_TC(tp, controller_names);
	ATF_TP_ADD_TC(tp, controller_descriptor_rights);
	ATF_TP_ADD_TC(tp, controller_channel_exchange);
	ATF_TP_ADD_TC(tp, controller_pending_cleanup);
	return (atf_no_error());
}
