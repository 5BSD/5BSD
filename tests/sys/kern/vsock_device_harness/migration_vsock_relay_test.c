/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "migration_vsock_relay.c"

struct relay_party {
	int stream;
	struct migration_vsock_relay_endpoint endpoint;
	int error;
};

static void *
relay_thread(void *arg)
{
	struct relay_party *party = arg;

	party->error = migration_vsock_relay_run(party->stream,
	    &party->endpoint, 1);
	return (NULL);
}

static void
read_exact(int fd, void *buf, size_t len)
{
	uint8_t *bytes = buf;
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = read(fd, bytes + off, len - off);
		ATF_REQUIRE_MSG(n > 0, "read returned %zd at %zu/%zu: %s",
		    n, off, len, strerror(errno));
		off += (size_t)n;
	}
}

ATF_TC_WITHOUT_HEAD(stream_bidirectional_and_half_close);
ATF_TC_BODY(stream_bidirectional_and_half_close, tc)
{
	struct relay_party a, b;
	pthread_t ta, tb;
	char buf[16];
	int net[2], left[2], right[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, net), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, left), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, right), 0);
	a = (struct relay_party) { .stream = net[0],
	    .endpoint = { left[0], VSOCK_MIGRATION_TYPE_STREAM } };
	b = (struct relay_party) { .stream = net[1],
	    .endpoint = { right[0], VSOCK_MIGRATION_TYPE_STREAM } };
	ATF_REQUIRE_EQ(pthread_create(&ta, NULL, relay_thread, &a), 0);
	ATF_REQUIRE_EQ(pthread_create(&tb, NULL, relay_thread, &b), 0);
	ATF_REQUIRE_EQ(write(left[1], "left-to-right", 13), 13);
	read_exact(right[1], buf, 13);
	ATF_CHECK_EQ(memcmp(buf, "left-to-right", 13), 0);
	ATF_REQUIRE_EQ(write(right[1], "return", 6), 6);
	read_exact(left[1], buf, 6);
	ATF_CHECK_EQ(memcmp(buf, "return", 6), 0);
	ATF_REQUIRE_EQ(shutdown(left[1], SHUT_WR), 0);
	ATF_CHECK_EQ(read(right[1], buf, sizeof(buf)), 0);
	ATF_REQUIRE_EQ(shutdown(right[1], SHUT_WR), 0);
	ATF_CHECK_EQ(read(left[1], buf, sizeof(buf)), 0);
	ATF_REQUIRE_EQ(pthread_join(ta, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(tb, NULL), 0);
	ATF_CHECK_EQ(a.error, 0);
	ATF_CHECK_EQ(b.error, 0);
	close(left[0]); close(left[1]);
	close(right[0]); close(right[1]);
	close(net[0]); close(net[1]);
}

ATF_TC_WITHOUT_HEAD(seqpacket_preserves_record_boundaries);
ATF_TC_BODY(seqpacket_preserves_record_boundaries, tc)
{
	struct relay_party a, b;
	struct iovec iov;
	struct msghdr msg;
	pthread_t ta, tb;
	char buf[256];
	int net[2], left[2], right[2];
	ssize_t n;

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, net), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, left), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, right), 0);
	a = (struct relay_party) { .stream = net[0],
	    .endpoint = { left[0], VSOCK_MIGRATION_TYPE_SEQPACKET } };
	b = (struct relay_party) { .stream = net[1],
	    .endpoint = { right[0], VSOCK_MIGRATION_TYPE_SEQPACKET } };
	ATF_REQUIRE_EQ(pthread_create(&ta, NULL, relay_thread, &a), 0);
	ATF_REQUIRE_EQ(pthread_create(&tb, NULL, relay_thread, &b), 0);
	ATF_REQUIRE_EQ(send(left[1], "first", 5, MSG_EOR), 5);
	ATF_REQUIRE_EQ(send(left[1], "second", 6, MSG_EOR), 6);
	for (int i = 0; i < 2; i++) {
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		n = recvmsg(right[1], &msg, 0);
		ATF_REQUIRE_EQ(n, i == 0 ? 5 : 6);
		ATF_CHECK((msg.msg_flags & MSG_EOR) != 0);
		ATF_CHECK_EQ(memcmp(buf, i == 0 ? "first" : "second",
		    (size_t)n), 0);
	}
	ATF_REQUIRE_EQ(shutdown(left[1], SHUT_WR), 0);
	ATF_CHECK_EQ(recv(right[1], buf, sizeof(buf), 0), 0);
	ATF_REQUIRE_EQ(shutdown(right[1], SHUT_WR), 0);
	ATF_CHECK_EQ(recv(left[1], buf, sizeof(buf), 0), 0);
	ATF_REQUIRE_EQ(pthread_join(ta, NULL), 0);
	ATF_REQUIRE_EQ(pthread_join(tb, NULL), 0);
	ATF_CHECK_EQ(a.error, 0);
	ATF_CHECK_EQ(b.error, 0);
	close(left[0]); close(left[1]);
	close(right[0]); close(right[1]);
	close(net[0]); close(net[1]);
}

ATF_TC_WITHOUT_HEAD(rejects_malformed_frame);
ATF_TC_BODY(rejects_malformed_frame, tc)
{
	struct relay_party party;
	pthread_t tid;
	uint8_t header[RELAY_HEADER_SIZE] = { 0 };
	int net[2], local[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, net), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, local), 0);
	party = (struct relay_party) { .stream = net[0],
	    .endpoint = { local[0], VSOCK_MIGRATION_TYPE_STREAM } };
	ATF_REQUIRE_EQ(pthread_create(&tid, NULL, relay_thread, &party), 0);
	ATF_REQUIRE_EQ(write(net[1], header, sizeof(header)),
	    (ssize_t)sizeof(header));
	ATF_REQUIRE_EQ(pthread_join(tid, NULL), 0);
	ATF_CHECK_EQ(party.error, EBADMSG);
	le32enc(header, RELAY_MAGIC);
	le32enc(header + 4, 0);
	le32enc(header + 8, RELAY_DATA);
	le32enc(header + 12, 0);
	ATF_REQUIRE_EQ(pthread_create(&tid, NULL, relay_thread, &party), 0);
	ATF_REQUIRE_EQ(write(net[1], header, sizeof(header)),
	    (ssize_t)sizeof(header));
	ATF_REQUIRE_EQ(pthread_join(tid, NULL), 0);
	ATF_CHECK_EQ(party.error, EBADMSG);
	close(local[0]); close(local[1]);
	close(net[0]); close(net[1]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, stream_bidirectional_and_half_close);
	ATF_TP_ADD_TC(tp, seqpacket_preserves_record_boundaries);
	ATF_TP_ADD_TC(tp, rejects_malformed_frame);
	return (atf_no_error());
}
