/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "migration_vsock_relay.c"
#include "migration_vsock_owner.c"

struct dest_relay {
	int net;
	struct migration_vsock_relay_endpoint endpoint;
	int error;
};

static void *
run_dest_relay(void *arg)
{
	struct dest_relay *dest = arg;

	dest->error = migration_vsock_relay_run(dest->net,
	    &dest->endpoint, 1);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(owner_cancel_preserves_source_and_activate_relays);
ATF_TC_BODY(owner_cancel_preserves_source_and_activate_relays, tc)
{
	struct migration_vsock_relay_endpoint source;
	struct dest_relay dest;
	struct pollfd pollfd;
	pthread_t tid;
	pid_t owner;
	char buf[16];
	int net[2], left[2], right[2], status;

	(void)tc;
	ATF_REQUIRE_EQ(migration_vsock_owner_start(&owner), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, net), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, left), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, right), 0);
	source = (struct migration_vsock_relay_endpoint) {
	    .fd = left[0], .type = VSOCK_MIGRATION_TYPE_STREAM };
	ATF_REQUIRE_EQ(migration_vsock_owner_prepare(net[0], &source, 1), 0);
	ATF_REQUIRE_EQ(write(left[1], "kept", 4), 4);
	pollfd = (struct pollfd) { .fd = net[1], .events = POLLIN };
	ATF_CHECK_EQ(poll(&pollfd, 1, 50), 0);
	ATF_REQUIRE_EQ(migration_vsock_owner_cancel(), 0);
	ATF_REQUIRE_EQ(read(left[0], buf, 4), 4);
	ATF_CHECK_EQ(memcmp(buf, "kept", 4), 0);

	dest = (struct dest_relay) { .net = net[1],
	    .endpoint = { right[0], VSOCK_MIGRATION_TYPE_STREAM } };
	ATF_REQUIRE_EQ(pthread_create(&tid, NULL, run_dest_relay, &dest), 0);
	ATF_REQUIRE_EQ(migration_vsock_owner_prepare(net[0], &source, 1), 0);
	ATF_REQUIRE_EQ(migration_vsock_owner_activate(), 0);
	close(net[0]);
	close(left[0]);
	ATF_REQUIRE_EQ(write(left[1], "moved", 5), 5);
	ATF_REQUIRE_EQ(read(right[1], buf, 5), 5);
	ATF_CHECK_EQ(memcmp(buf, "moved", 5), 0);
	ATF_REQUIRE_EQ(write(right[1], "back", 4), 4);
	ATF_REQUIRE_EQ(read(left[1], buf, 4), 4);
	ATF_CHECK_EQ(memcmp(buf, "back", 4), 0);
	ATF_REQUIRE_EQ(shutdown(left[1], SHUT_WR), 0);
	ATF_CHECK_EQ(read(right[1], buf, sizeof(buf)), 0);
	ATF_REQUIRE_EQ(shutdown(right[1], SHUT_WR), 0);
	ATF_CHECK_EQ(read(left[1], buf, sizeof(buf)), 0);
	ATF_REQUIRE_EQ(pthread_join(tid, NULL), 0);
	ATF_CHECK_EQ(dest.error, 0);
	ATF_REQUIRE_EQ(waitpid(owner, &status, 0), owner);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(net[1]);
	close(left[1]);
	close(right[0]);
	close(right[1]);
}

ATF_TC_WITHOUT_HEAD(owner_prepare_batches_maximum_connections);
ATF_TC_BODY(owner_prepare_batches_maximum_connections, tc)
{
	struct migration_vsock_relay_endpoint
	    endpoints[VSOCK_MIGRATION_MAX_CONNS];
	int pairs[VSOCK_MIGRATION_MAX_CONNS][2];
	int net[2], status;
	pid_t owner;

	(void)tc;
	ATF_REQUIRE_EQ(migration_vsock_owner_start(&owner), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, net), 0);
	for (size_t i = 0; i < VSOCK_MIGRATION_MAX_CONNS; i++) {
		ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0,
		    pairs[i]), 0);
		endpoints[i] = (struct migration_vsock_relay_endpoint) {
		    .fd = pairs[i][0],
		    .type = VSOCK_MIGRATION_TYPE_STREAM,
		};
	}
	ATF_REQUIRE_EQ(migration_vsock_owner_prepare(net[0], endpoints,
	    VSOCK_MIGRATION_MAX_CONNS), 0);
	ATF_REQUIRE_EQ(migration_vsock_owner_cancel(), 0);
	for (size_t i = 0; i < VSOCK_MIGRATION_MAX_CONNS; i++) {
		close(pairs[i][0]);
		close(pairs[i][1]);
	}
	close(net[0]);
	close(net[1]);
	migration_vsock_owner_detach();
	ATF_REQUIRE_EQ(waitpid(owner, &status, 0), owner);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

ATF_TC_WITHOUT_HEAD(owner_incomplete_batch_cannot_activate);
ATF_TC_BODY(owner_incomplete_batch_cannot_activate, tc)
{
	struct migration_vsock_relay_endpoint endpoint;
	char byte;
	int net[2], local[2], status;
	pid_t owner;

	(void)tc;
	ATF_REQUIRE_EQ(migration_vsock_owner_start(&owner), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, net), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, local), 0);
	endpoint = (struct migration_vsock_relay_endpoint) {
	    .fd = local[0], .type = VSOCK_MIGRATION_TYPE_STREAM,
	};
	/* Admit one descriptor but declare two; the second batch never arrives. */
	ATF_REQUIRE_EQ(owner_request(OWNER_PREPARE, net[0], &endpoint,
	    1, 2), 0);
	ATF_REQUIRE_EQ(migration_vsock_owner_activate(), EINVAL);
	/* A rejected second prepare must release the first owner's copies. */
	ATF_REQUIRE_EQ(migration_vsock_owner_prepare(net[0], &endpoint, 1),
	    EINVAL);
	ATF_REQUIRE_EQ(migration_vsock_owner_prepare(net[0], &endpoint, 1), 0);
	ATF_REQUIRE_EQ(write(local[1], "q", 1), 1);
	ATF_REQUIRE_EQ(migration_vsock_owner_cancel(), 0);
	ATF_REQUIRE_EQ(read(local[0], &byte, 1), 1);
	ATF_CHECK_EQ(byte, 'q');
	close(local[0]);
	close(local[1]);
	close(net[0]);
	close(net[1]);
	migration_vsock_owner_detach();
	ATF_REQUIRE_EQ(waitpid(owner, &status, 0), owner);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, owner_cancel_preserves_source_and_activate_relays);
	ATF_TP_ADD_TC(tp, owner_prepare_batches_maximum_connections);
	ATF_TP_ADD_TC(tp, owner_incomplete_batch_cannot_activate);
	return (atf_no_error());
}
