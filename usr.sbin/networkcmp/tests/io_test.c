/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "io.h"
#include "session.h"

struct io_fixture {
	struct networkcmp_session session;
	struct networkcmp_handle handle;
	int peer;
};

static void
fixture_open(struct io_fixture *fixture, int type, uint32_t network_type)
{
	int pair[2];

	memset(fixture, 0, sizeof(*fixture));
	ATF_REQUIRE_EQ(0, networkcmp_session_init(&fixture->session, 2));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, type, 0, pair));
	ATF_REQUIRE_EQ(0, networkcmp_session_allocate(&fixture->session, pair[0],
	    NETWORKCMP_AF_INET4, network_type, &fixture->handle));
	fixture->peer = pair[1];
}

static void
fixture_close(struct io_fixture *fixture)
{

	networkcmp_session_destroy(&fixture->session);
	ATF_REQUIRE_EQ(0, close(fixture->peer));
}

ATF_TC(stream_round_trip_and_eof);
ATF_TC_HEAD(stream_round_trip_and_eof, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "inline stream IO transfers bytes and reports orderly EOF");
}
ATF_TC_BODY(stream_round_trip_and_eof, tc)
{
	struct io_fixture fixture;
	struct {
		struct networkcmp_inline_request request;
		char data[16];
	} send_request;
	struct networkcmp_inline_request recv_request;
	struct networkcmp_inline_reply reply;
	char output[16];

	fixture_open(&fixture, SOCK_STREAM, NETWORKCMP_SOCK_STREAM);
	memset(&send_request, 0, sizeof(send_request));
	send_request.request.socket = fixture.handle;
	send_request.request.length = 5;
	memcpy(send_request.data, "hello", 5);
	ATF_REQUIRE_EQ(0, networkcmp_io_send(&fixture.session,
	    &send_request.request, &reply));
	ATF_CHECK_EQ(5, reply.length);
	ATF_REQUIRE_EQ(5, recv(fixture.peer, output, sizeof(output), 0));
	ATF_CHECK_EQ(0, memcmp(output, "hello", 5));

	ATF_REQUIRE_EQ(5, send(fixture.peer, "world", 5, 0));
	memset(&recv_request, 0, sizeof(recv_request));
	recv_request.socket = fixture.handle;
	recv_request.length = sizeof(output);
	ATF_REQUIRE_EQ(0, networkcmp_io_recv(&fixture.session, &recv_request,
	    &reply, output));
	ATF_CHECK_EQ(5, reply.length);
	ATF_CHECK_EQ(0, reply.flags);
	ATF_CHECK_EQ(0, memcmp(output, "world", 5));

	ATF_REQUIRE_EQ(0, shutdown(fixture.peer, SHUT_WR));
	ATF_REQUIRE_EQ(0, networkcmp_io_recv(&fixture.session, &recv_request,
	    &reply, output));
	ATF_CHECK_EQ(0, reply.length);
	ATF_CHECK_EQ(NETWORKCMP_IO_F_EOF, reply.flags);
	fixture_close(&fixture);
}

ATF_TC(datagram_records_and_truncation);
ATF_TC_HEAD(datagram_records_and_truncation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "inline datagram IO preserves records and bounds truncated replies");
}
ATF_TC_BODY(datagram_records_and_truncation, tc)
{
	struct io_fixture fixture;
	struct networkcmp_inline_request request;
	struct networkcmp_inline_reply reply;
	char output[4];

	fixture_open(&fixture, SOCK_DGRAM, NETWORKCMP_SOCK_DGRAM);
	ATF_REQUIRE_EQ(8, send(fixture.peer, "datagram", 8, 0));
	memset(&request, 0, sizeof(request));
	request.socket = fixture.handle;
	request.length = sizeof(output);
	ATF_REQUIRE_EQ(0, networkcmp_io_recv(&fixture.session, &request,
	    &reply, output));
	ATF_CHECK_EQ(sizeof(output), reply.length);
	ATF_CHECK_EQ(NETWORKCMP_IO_F_TRUNCATED, reply.flags);
	ATF_CHECK_EQ(0, memcmp(output, "data", sizeof(output)));
	fixture_close(&fixture);
}

ATF_TC(timeout_and_nonblocking);
ATF_TC_HEAD(timeout_and_nonblocking, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "provider inline receive is always nonblocking");
}
ATF_TC_BODY(timeout_and_nonblocking, tc)
{
	struct io_fixture fixture;
	struct networkcmp_inline_request request;
	struct networkcmp_inline_reply reply;
	char output[1];

	fixture_open(&fixture, SOCK_STREAM, NETWORKCMP_SOCK_STREAM);
	memset(&request, 0, sizeof(request));
	request.socket = fixture.handle;
	request.length = sizeof(output);
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_io_recv(&fixture.session, &request,
	    &reply, output));
	ATF_CHECK_EQ(EAGAIN, errno);
	request.timeout_ms = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_io_recv(&fixture.session, &request,
	    &reply, output));
	ATF_CHECK_EQ(EINVAL, errno);
	fixture_close(&fixture);
}

ATF_TC(argument_and_handle_validation);
ATF_TC_HEAD(argument_and_handle_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "inline IO rejects malformed requests and stale handles");
}
ATF_TC_BODY(argument_and_handle_validation, tc)
{
	struct io_fixture fixture;
	struct {
		struct networkcmp_inline_request request;
		char data[1];
	} wire;
	struct networkcmp_inline_reply reply;
	char output[1];

	fixture_open(&fixture, SOCK_STREAM, NETWORKCMP_SOCK_STREAM);
	memset(&wire, 0, sizeof(wire));
	wire.request.socket = fixture.handle;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_io_send(&fixture.session, &wire.request,
	    &reply));
	ATF_CHECK_EQ(EINVAL, errno);
	wire.request.length = 1;
	wire.request.socket.generation++;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_io_send(&fixture.session, &wire.request,
	    &reply));
	ATF_CHECK_EQ(ESTALE, errno);
	wire.request.socket = fixture.handle;
	wire.request.timeout_ms = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_io_send(&fixture.session, &wire.request,
	    &reply));
	ATF_CHECK_EQ(EINVAL, errno);
	wire.request.timeout_ms = NETWORKCMP_IO_TIMEOUT_MAX + 1;
	errno = 0;
	ATF_CHECK_EQ(-1, networkcmp_io_recv(&fixture.session, &wire.request,
	    &reply, output));
	ATF_CHECK_EQ(EINVAL, errno);
	fixture_close(&fixture);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, stream_round_trip_and_eof);
	ATF_TP_ADD_TC(tp, datagram_records_and_truncation);
	ATF_TP_ADD_TC(tp, timeout_and_nonblocking);
	ATF_TP_ADD_TC(tp, argument_and_handle_validation);
	return (atf_no_error());
}
