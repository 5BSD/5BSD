/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/socket.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <authorityctl.h>

static void
send_all(int fd, const void *data, size_t length)
{
	const char *bytes;
	ssize_t amount;
	size_t offset;

	bytes = data;
	for (offset = 0; offset < length; ) {
		amount = send(fd, bytes + offset, length - offset, MSG_NOSIGNAL);
		ATF_REQUIRE(amount > 0);
		offset += (size_t)amount;
	}
}

static void
write_reply(int fd, uint32_t status, uint32_t textlen, const char *text)
{
	struct ctl_reply reply;
	struct ctl_request request;
	ssize_t n;

	n = read(fd, &request, sizeof(request));
	ATF_REQUIRE_EQ_MSG(n, (ssize_t)sizeof(request),
	    "server did not receive a complete request");
	memset(&reply, 0, sizeof(reply));
	reply.status = status;
	reply.flags = textlen;
	send_all(fd, &reply, sizeof(reply));
	if (text != NULL && textlen != 0)
		send_all(fd, text, textlen);
}

static pid_t
spawn_reply_server(int fd, uint32_t status, uint32_t textlen,
    const char *text)
{
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		write_reply(fd, status, textlen, text);
		_exit(0);
	}
	return (pid);
}

static void
reap_ok(pid_t pid)
{
	int status;

	ATF_REQUIRE_EQ(waitpid(pid, &status, 0), pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
}

ATF_TC_WITHOUT_HEAD(dead_peer_no_sigpipe);
ATF_TC_BODY(dead_peer_no_sigpipe, tc)
{
	int sv[2];
	struct authorityctl_status status;
	char summary[8];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	ATF_REQUIRE_EQ(close(sv[1]), 0);
	ATF_REQUIRE_EQ(authorityctl_status(sv[0], &status, summary,
	    sizeof(summary)), EPIPE);
	ATF_REQUIRE_EQ(close(sv[0]), 0);
}

ATF_TC_WITHOUT_HEAD(oversized_summary_rejected);
ATF_TC_BODY(oversized_summary_rejected, tc)
{
	struct authorityctl_status status;
	char summary[32];
	pid_t pid;
	int sv[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	pid = spawn_reply_server(sv[1], 0, AUTHORITYCTL_SUMMARY_MAX + 1, NULL);
	ATF_REQUIRE_EQ(close(sv[1]), 0);
	ATF_REQUIRE_EQ(authorityctl_status(sv[0], &status, summary,
	    sizeof(summary)), EPROTO);
	ATF_REQUIRE_EQ(close(sv[0]), 0);
	reap_ok(pid);
}

ATF_TC_WITHOUT_HEAD(summary_truncates_safely);
ATF_TC_BODY(summary_truncates_safely, tc)
{
	struct authorityctl_status status;
	const char payload[] = "abcdefgh";
	char summary[5];
	pid_t pid;
	int sv[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	pid = spawn_reply_server(sv[1], 0, sizeof(payload) - 1, payload);
	ATF_REQUIRE_EQ(close(sv[1]), 0);
	ATF_REQUIRE_EQ(authorityctl_status(sv[0], &status, summary,
	    sizeof(summary)), 0);
	ATF_REQUIRE_STREQ(summary, "abcd");
	ATF_REQUIRE_EQ(close(sv[0]), 0);
	reap_ok(pid);
}

ATF_TC_WITHOUT_HEAD(truncated_reply_detected);
ATF_TC_BODY(truncated_reply_detected, tc)
{
	struct authorityctl_status status;
	struct ctl_request request;
	char summary[8];
	pid_t pid;
	int sv[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		ATF_REQUIRE_EQ(read(sv[1], &request, sizeof(request)),
		    (ssize_t)sizeof(request));
		(void)close(sv[1]);
		_exit(0);
	}
	ATF_REQUIRE_EQ(close(sv[1]), 0);
	ATF_REQUIRE_EQ(authorityctl_status(sv[0], &status, summary,
	    sizeof(summary)), ECONNRESET);
	ATF_REQUIRE_EQ(close(sv[0]), 0);
	reap_ok(pid);
}

ATF_TC_WITHOUT_HEAD(path_too_long);
ATF_TC_BODY(path_too_long, tc)
{
	char path[PATH_MAX];

	(void)tc;
	memset(path, 'a', sizeof(path));
	path[sizeof(path) - 1] = '\0';
	errno = 0;
	ATF_REQUIRE_EQ(authorityctl_open(path), -1);
	ATF_REQUIRE_EQ(errno, ENAMETOOLONG);
}

ATF_TC_WITHOUT_HEAD(daemon_status_preserved);
ATF_TC_BODY(daemon_status_preserved, tc)
{
	struct authorityctl_status status;
	char summary[8];
	pid_t pid;
	int sv[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	pid = spawn_reply_server(sv[1], EPERM, 0, NULL);
	ATF_REQUIRE_EQ(close(sv[1]), 0);
	ATF_REQUIRE_EQ(authorityctl_status(sv[0], &status, summary,
	    sizeof(summary)), EPERM);
	ATF_REQUIRE_EQ(status.error, EPERM);
	ATF_REQUIRE_STREQ(summary, "");
	ATF_REQUIRE_EQ(close(sv[0]), 0);
	reap_ok(pid);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, dead_peer_no_sigpipe);
	ATF_TP_ADD_TC(tp, oversized_summary_rejected);
	ATF_TP_ADD_TC(tp, summary_truncates_safely);
	ATF_TP_ADD_TC(tp, truncated_reply_detected);
	ATF_TP_ADD_TC(tp, path_too_long);
	ATF_TP_ADD_TC(tp, daemon_status_preserved);
	return (atf_no_error());
}
