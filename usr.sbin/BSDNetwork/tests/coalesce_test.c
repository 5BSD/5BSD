/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Resolver coalescing in the real BSDNetwork worker code: identical RESOLVE
 * requests join one lookup (bounded), a different one is refused with EBUSY,
 * and every retained request is answered and released, even when a reply
 * cannot be delivered.  The generated reply and the request references are
 * replaced by counters.
 */
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <networkcmp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

struct fidl_bsd_request { unsigned token; unsigned references; };
struct fidl_bsd_connection;
struct bsd_network_v1_Network_Resolve_Result;
static unsigned replies, freed, fail_at;

#define bsd_network_v1_Network_Resolve_reply fake_reply
#define fidl_bsd_request_retain fake_retain
#define fidl_bsd_request_release fake_release
#define fidl_bsd_connection_close fake_close
#define NETWORKCMP_TESTING
#include "../networkcmp.c"

int
fake_reply(struct fidl_bsd_connection *connection __unused,
    struct fidl_bsd_request *request,
    const struct bsd_network_v1_Network_Resolve_Result *result)
{
	ATF_CHECK_EQ(request->token, replies);
	ATF_CHECK_EQ(bsd_network_v1_Network_Resolve_Result_err_tag, result->tag);
	ATF_CHECK_EQ(EOPNOTSUPP, (int)result->value.err);
	if (++replies == fail_at)
		return (EPIPE);
	return (0);
}

void
fake_retain(struct fidl_bsd_request *request)
{
	request->references++;
}

void
fake_release(struct fidl_bsd_request *request)
{
	if (--request->references == 0) {
		freed++;
		free(request);
	}
}

void
fake_close(struct fidl_bsd_connection *connection __unused, int error)
{
	ATF_CHECK_EQ(EPIPE, error);
}

/* A request as the bindings hand it to a handler: one reference, theirs. */
static struct fidl_bsd_request *
incoming(unsigned token)
{
	struct fidl_bsd_request *request = calloc(1, sizeof(*request));

	ATF_REQUIRE(request != NULL);
	request->token = token;
	request->references = 1;
	return (request);
}

/* The bindings drop their reference when the handler returns. */
static void
handler_returns(struct fidl_bsd_request *request)
{
	fake_release(request);
}

static void
check_coalescing(bool delivery_failure)
{
	struct session_state state = { .label = "test", .resolver_timeout_ms = 1000 };
	struct bsd_network_v1_ResolveRequest wire = {
		.host = "localhost", .host_size = 9, .service = "",
		.service_size = 0, .max_results = 1
	};
	struct fidl_bsd_request *request;
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
	request = incoming(0);
	ATF_REQUIRE_EQ(0, start_resolve(&state, request, &wire));
	handler_returns(request);
	ATF_REQUIRE_EQ(1, read(ready[0], &byte, 1));
	deadline = state.resolver_deadline_ns;
	request = incoming(99);
	wire.host = "xocalhost";
	ATF_CHECK_ERRNO(EBUSY, start_resolve(&state, request, &wire) == -1);
	handler_returns(request);
	wire.host = "localhost";
	for (unsigned i = 1; i < NETWORKCMP_RESOLVE_WAITERS; i++) {
		request = incoming(i);
		ATF_REQUIRE_EQ(0, start_resolve(&state, request, &wire));
		handler_returns(request);
		ATF_CHECK_EQ(deadline, state.resolver_deadline_ns);
	}
	request = incoming(99);
	ATF_CHECK_ERRNO(EBUSY, start_resolve(&state, request, &wire) == -1);
	handler_returns(request);
	ATF_CHECK_EQ(2, freed);
	byte = 1;
	ATF_REQUIRE_EQ(1, write(release[1], &byte, 1));
	pollfd = (struct pollfd){ .fd = state.resolver_pipe[0], .events = POLLIN };
	/* The resolver runs the real lookup only now; allow an emulated guest. */
	ATF_REQUIRE_EQ(1, poll(&pollfd, 1, 30000));
	ATF_REQUIRE_EQ(0, finish_resolve(&state));
	/* A failed delivery is terminal: later waiters get no reply. */
	ATF_CHECK_EQ(delivery_failure ? 3 : NETWORKCMP_RESOLVE_WAITERS, replies);
	ATF_CHECK_EQ(delivery_failure ? EPIPE : 0, state.terminal_error);
	ATF_CHECK_EQ(NETWORKCMP_RESOLVE_WAITERS + 2, freed);
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
