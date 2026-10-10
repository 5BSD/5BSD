/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <oes_broker_protocol.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
struct channel_message {
	struct oes_broker_message wire;
	size_t length, nfds;
};
static int opens, frees, sends, original_fd, delivered_fd = -1, open_error;
static bool send_failure;
static struct oes_broker_message response;
static int
fake_factory(int root)
{
	int p[2];
	(void)root;
	opens++;
	if (open_error)
		return (errno = open_error, -1);
	ATF_REQUIRE_EQ(0, pipe(p));
	close(p[1]);
	return (original_fd = p[0]);
}
static const void *
fake_data(const struct channel_message *m)
{
	return (&m->wire);
}
static size_t
fake_length(const struct channel_message *m)
{
	return (m->length);
}
static size_t
fake_fds(const struct channel_message *m)
{
	return (m->nfds);
}
static void
fake_free(struct channel_message *m)
{
	(void)m;
	frees++;
}
static int
fake_reply(struct channel_message *m, const struct channel_outgoing *out)
{
	(void)m;
	sends++;
	response = *(const struct oes_broker_message *)out->data;
	ATF_CHECK_EQ(0,
	    oes_broker_validate(out->data, out->length, out->nfds, true));
	if (send_failure)
		return (errno = EPIPE, -1);
	if (out->nfds) {
		delivered_fd = dup(*out->fds);
		ATF_REQUIRE(delivered_fd >= 0);
	}
	return (0);
}
#define bsdfilesystem_oes_open_notify fake_factory
#define channel_message_data	      fake_data
#define channel_message_length	      fake_length
#define channel_message_fd_count      fake_fds
#define channel_message_free	      fake_free
#define channel_send_reply	      fake_reply
#include "../oes_session.c"
static struct channel_message
message(void)
{
	return ((
	    struct channel_message) { .wire = { .magic = OES_BROKER_MAGIC,
					  .version = OES_BROKER_VERSION,
					  .operation = OES_BROKER_OPEN_NOTIFY },
	    .length = sizeof(struct oes_broker_message) });
}
ATF_TC_WITHOUT_HEAD(reject_before_open);
ATF_TC_BODY(reject_before_open, tc)
{
	for (int i = 0; i < 3; i++) {
		struct oes_factory_session state = { .rootfd = 1 };
		struct channel_message m = message();
		if (i == 0)
			m.length--;
		else if (i == 1)
			m.nfds = 1;
		else
			m.wire.reserved = 1;
		oes_factory_request(NULL, &m, &state);
		ATF_CHECK_EQ(EPROTO, response.status);
		ATF_CHECK(state.done);
	}
	ATF_CHECK_EQ(0, opens);
	ATF_CHECK_EQ(3, frees);
}
ATF_TC_WITHOUT_HEAD(one_grant_and_local_close);
ATF_TC_BODY(one_grant_and_local_close, tc)
{
	struct oes_factory_session state = { .rootfd = 1 };
	struct channel_message m = message();
	oes_factory_request(NULL, &m, &state);
	ATF_CHECK_EQ(0, response.status);
	ATF_CHECK_ERRNO(EBADF, fcntl(original_fd, F_GETFD) == -1);
	ATF_CHECK(fcntl(delivered_fd, F_GETFD) != -1);
	close(delivered_fd);
	oes_factory_request(NULL, &m, &state);
	ATF_CHECK_EQ(1, opens);
	ATF_CHECK_EQ(1, sends);
	ATF_CHECK_EQ(2, frees);
}
ATF_TC_WITHOUT_HEAD(failed_delivery_closes);
ATF_TC_BODY(failed_delivery_closes, tc)
{
	struct oes_factory_session state = { .rootfd = 1 };
	struct channel_message m = message();
	send_failure = true;
	oes_factory_request(NULL, &m, &state);
	ATF_CHECK_EQ(EPIPE, state.send_error);
	ATF_CHECK_ERRNO(EBADF, fcntl(original_fd, F_GETFD) == -1);
}
ATF_TC_WITHOUT_HEAD(factory_error_has_no_descriptor);
ATF_TC_BODY(factory_error_has_no_descriptor, tc)
{
	struct oes_factory_session state = { .rootfd = 1 };
	struct channel_message m = message();
	open_error = ENXIO;
	oes_factory_request(NULL, &m, &state);
	ATF_CHECK_EQ(ENXIO, response.status);
	ATF_CHECK_EQ(-1, delivered_fd);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reject_before_open);
	ATF_TP_ADD_TC(tp, one_grant_and_local_close);
	ATF_TP_ADD_TC(tp, failed_delivery_closes);
	ATF_TP_ADD_TC(tp, factory_error_has_no_descriptor);
	return (atf_no_error());
}
