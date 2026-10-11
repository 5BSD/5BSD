/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <channel.h>
#include <networkcmp.h>
#include <poll.h>
#include <stdlib.h>
#include <errno.h>
struct channel_message { unsigned token; };
static unsigned replies, freed, fail_at;
static int
fake_reply(struct channel_message *message, const struct channel_outgoing *out)
{
	const struct networkcmp_msg *header = out->data;
	ATF_CHECK_EQ(message->token, replies);
	ATF_CHECK_EQ(-EOPNOTSUPP, header->status);
	if (++replies == fail_at)
		return (errno = EPIPE, -1);
	return (0);
}
static void
fake_free(struct channel_message *message)
{
	freed++;
	free(message);
}
#define channel_send_reply fake_reply
#define channel_message_free fake_free
#define NETWORKCMP_TESTING
#include "../networkcmp.c"

static void
check_coalescing(bool delivery_failure)
{
	struct session_state state = { .label = "test", .resolver_timeout_ms = 1000 };
	struct {
		struct networkcmp_msg header;
		struct networkcmp_resolve_request request;
		char host[10];
	} wire = { .request = { .host_length = 9, .max_results = 1 },
	    .host = "localhost" };
	struct channel_message *message;
	int ready[2], release[2];
	struct pollfd pollfd;
	char byte;
	uint64_t deadline;

	replies = freed = 0;
	fail_at = delivery_failure ? 3 : 0;
	ATF_REQUIRE_EQ(0, pipe(ready));
	ATF_REQUIRE_EQ(0, pipe(release));
	ATF_REQUIRE_EQ(0, pipe2(state.resolver_pipe, O_NONBLOCK));
	state.test_ready_fd = ready[1];
	state.test_release_fd = release[0];
	ATF_REQUIRE_EQ(0, networkcmp_message_init(&wire.header, NETWORKCMP_OP_RESOLVE, 0));
	message = calloc(1, sizeof(*message));
	ATF_REQUIRE(message != NULL);
	ATF_REQUIRE_EQ(0, start_resolve(&state, message, &wire.header));
	ATF_REQUIRE_EQ(1, read(ready[0], &byte, 1));
	deadline = state.resolver_deadline_ns;
	message = calloc(1, sizeof(*message));
	ATF_REQUIRE(message != NULL);
	wire.host[0] = 'x';
	ATF_CHECK_ERRNO(EBUSY, start_resolve(&state, message, &wire.header) == -1);
	wire.host[0] = 'l';
	free(message);
	for (unsigned i = 1; i < NETWORKCMP_RESOLVE_WAITERS; i++) {
		message = calloc(1, sizeof(*message));
		ATF_REQUIRE(message != NULL);
		message->token = i;
		ATF_REQUIRE_EQ(0, start_resolve(&state, message, &wire.header));
		ATF_CHECK_EQ(deadline, state.resolver_deadline_ns);
	}
	message = calloc(1, sizeof(*message));
	ATF_REQUIRE(message != NULL);
	ATF_CHECK_ERRNO(EBUSY, start_resolve(&state, message, &wire.header) == -1);
	free(message);
	byte = 1;
	ATF_REQUIRE_EQ(1, write(release[1], &byte, 1));
	pollfd = (struct pollfd){ .fd = state.resolver_pipe[0], .events = POLLIN };
	/* The resolver runs the real lookup only now; allow an emulated guest. */
	ATF_REQUIRE_EQ(1, poll(&pollfd, 1, 30000));
	if (delivery_failure)
		ATF_CHECK_ERRNO(EPIPE, finish_resolve(&state) == -1);
	else
		ATF_REQUIRE_EQ(0, finish_resolve(&state));
	ATF_CHECK_EQ(delivery_failure ? 3 : NETWORKCMP_RESOLVE_WAITERS, replies);
	ATF_CHECK_EQ(NETWORKCMP_RESOLVE_WAITERS, freed);
	ATF_CHECK(state.resolver == NULL);
	ATF_CHECK_EQ(0, state.resolver_deadline_ns);
	close(ready[0]); close(ready[1]); close(release[0]); close(release[1]);
	close(state.resolver_pipe[0]); close(state.resolver_pipe[1]);
}
ATF_TC_WITHOUT_HEAD(bounded_duplicates);
ATF_TC_BODY(bounded_duplicates, tc) { check_coalescing(false); }
ATF_TC_WITHOUT_HEAD(failed_delivery_cleanup);
ATF_TC_BODY(failed_delivery_cleanup, tc) { check_coalescing(true); }
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bounded_duplicates);
	ATF_TP_ADD_TC(tp, failed_delivery_cleanup);
	return (atf_no_error());
}
