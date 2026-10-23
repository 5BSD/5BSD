/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "sockstream.c"

ATF_TC_WITHOUT_HEAD(short_message_is_rejected);
ATF_TC_BODY(short_message_is_rejected, tc)
{
	char buffer[4] = { 0 };
	int fds[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
	ATF_REQUIRE_EQ(write(fds[1], "ab", 2), 2);
	ATF_REQUIRE_EQ(shutdown(fds[1], SHUT_WR), 0);
	ATF_CHECK_EQ(stream_read(fds[0], buffer, sizeof(buffer)), -1);
	ATF_CHECK_EQ(errno, ECONNRESET);
	ATF_CHECK_EQ(memcmp(buffer, "ab", 2), 0);
	ATF_CHECK_EQ(stream_read(fds[0], buffer, sizeof(buffer)), 0);
	ATF_REQUIRE_EQ(close(fds[0]), 0);
	ATF_REQUIRE_EQ(close(fds[1]), 0);
}

ATF_TC_WITHOUT_HEAD(complete_message_round_trip);
ATF_TC_BODY(complete_message_round_trip, tc)
{
	char buffer[4] = { 0 };
	int fds[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
	ATF_REQUIRE_EQ(stream_write(fds[1], "abcd", 4), 4);
	ATF_REQUIRE_EQ(stream_read(fds[0], buffer, sizeof(buffer)), 4);
	ATF_CHECK_EQ(memcmp(buffer, "abcd", sizeof(buffer)), 0);
	ATF_REQUIRE_EQ(close(fds[0]), 0);
	ATF_REQUIRE_EQ(close(fds[1]), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, short_message_is_rejected);
	ATF_TP_ADD_TC(tp, complete_message_round_trip);
	return (atf_no_error());
}
