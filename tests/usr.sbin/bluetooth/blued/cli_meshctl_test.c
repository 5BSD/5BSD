/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshctl(8) client's reply reader.  meshd replies are a
 * single line of at most 2047 bytes plus '\n';
 * MESHCTL_REPLY_MAX (2050) must hold that line, the newline and the NUL, so a
 * maximum-size daemon reply is read back intact - the old 2048-byte buffer
 * truncated it.  As in cli_test.c, the shipping translation unit is
 * #include'd with main() renamed out of the way.
 */

#include <sys/socket.h>
#include <sys/wait.h>

#include <signal.h>

#define main meshctl_main_unused
#include "meshctl.c"
#undef main

#include <atf-c.h>

/* The longest daemon reply LINE (2047 payload bytes + '\n'): see
 * MESHD_CTL_REPLY_MAX in meshd.h; MESHCTL_REPLY_MAX = that + NUL. */
#define	REPLY_LINE_MAX	(MESHCTL_REPLY_MAX - 2)

/* Write all of buf to fd, then shut down the write side. */
static void
stage_reply(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t w = write(fd, buf + off, len - off);

		ATF_REQUIRE(w > 0);
		off += (size_t)w;
	}
	ATF_REQUIRE_EQ(0, shutdown(fd, SHUT_WR));
}

/* A maximum-size daemon reply (2047 bytes + '\n') is read back intact. */
ATF_TC_WITHOUT_HEAD(meshctl_readline_max_reply);
ATF_TC_BODY(meshctl_readline_max_reply, tc)
{
	char line[REPLY_LINE_MAX + 1];	/* 2047 payload + '\n' + NUL */
	char buf[MESHCTL_REPLY_MAX];
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	memset(line, 'A', REPLY_LINE_MAX - 1);
	line[0] = 'O';
	line[1] = 'K';
	line[REPLY_LINE_MAX - 1] = '\n';
	stage_reply(sp[1], line, REPLY_LINE_MAX);

	ATF_REQUIRE_EQ(REPLY_LINE_MAX,
	    meshctl_readline(sp[0], buf, sizeof(buf)));
	ATF_CHECK_EQ('\n', buf[REPLY_LINE_MAX - 1]);
	ATF_CHECK_EQ('\0', buf[REPLY_LINE_MAX]);
	line[REPLY_LINE_MAX - 1] = 'A';	/* compare payload bytes */
	ATF_CHECK_EQ(0, memcmp(buf, line, REPLY_LINE_MAX - 1));
	close(sp[0]);
	close(sp[1]);
}

/* One byte beyond the protocol maximum overflows the buffer: -1/EMSGSIZE. */
ATF_TC_WITHOUT_HEAD(meshctl_readline_overlong_reply);
ATF_TC_BODY(meshctl_readline_overlong_reply, tc)
{
	char line[REPLY_LINE_MAX + 2];
	char buf[MESHCTL_REPLY_MAX];
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	memset(line, 'B', sizeof(line) - 1);
	line[sizeof(line) - 1] = '\n';
	stage_reply(sp[1], line, sizeof(line));

	errno = 0;
	ATF_CHECK_EQ(-1, meshctl_readline(sp[0], buf, sizeof(buf)));
	ATF_CHECK_EQ(EMSGSIZE, errno);
	ATF_CHECK_EQ('\0', buf[sizeof(buf) - 1]);	/* NUL-terminated */
	close(sp[0]);
	close(sp[1]);
}

/*
 * A reply cut short by EOF is an I/O error, not a complete line.  meshd
 * disconnects a client whose reply queue overflows, so a partial "OK ..."
 * really can arrive; returning it as a finished line made meshctl_exchange()
 * report success for a reply it never fully received.  A clean EOF on a line
 * boundary still returns 0 so callers can report "daemon closed the
 * connection".
 */
ATF_TC_WITHOUT_HEAD(meshctl_readline_eof);
ATF_TC_BODY(meshctl_readline_eof, tc)
{
	char buf[MESHCTL_REPLY_MAX];
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	stage_reply(sp[1], "OK partial", 10);

	errno = 0;
	ATF_CHECK_EQ(-1, meshctl_readline(sp[0], buf, sizeof(buf)));
	ATF_CHECK_EQ(EPIPE, errno);
	ATF_CHECK_EQ(0, strcmp(buf, "OK partial"));	/* still terminated */
	close(sp[0]);
	close(sp[1]);

	/* A clean EOF with nothing buffered stays a 0-length read. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ATF_REQUIRE_EQ(0, shutdown(sp[1], SHUT_WR));
	ATF_CHECK_EQ(0, meshctl_readline(sp[0], buf, sizeof(buf)));
	close(sp[0]);
	close(sp[1]);
}

/*
 * meshctl_exchange() must not accept a truncated reply as a daemon "OK".
 */
ATF_TC_WITHOUT_HEAD(meshctl_exchange_truncated_reply);
ATF_TC_BODY(meshctl_exchange_truncated_reply, tc)
{
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	(void)signal(SIGPIPE, SIG_IGN);
	stage_reply(sp[1], "OK truncat", 10);

	ATF_CHECK_EQ(-1, meshctl_exchange(sp[0], "status"));
	close(sp[0]);
	close(sp[1]);
}

/*
 * meshctl.8 documents 2 for a connection/I/O error and reserves 1 for a
 * daemon ERR reply, so a dead daemon must not be indistinguishable from a
 * rejected command.  usage() shares the connection/usage code.
 */
ATF_TC_WITHOUT_HEAD(meshctl_connect_failure_exits_two);
ATF_TC_BODY(meshctl_connect_failure_exits_two, tc)
{
	pid_t child;
	int status;

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		(void)freopen("/dev/null", "w", stderr);
		(void)meshctl_connect("/nonexistent/meshd-not-here.sock");
		_exit(99);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(2, WEXITSTATUS(status));

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		(void)freopen("/dev/null", "w", stderr);
		usage();
		_exit(99);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(2, WEXITSTATUS(status));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, meshctl_readline_max_reply);
	ATF_TP_ADD_TC(tp, meshctl_readline_overlong_reply);
	ATF_TP_ADD_TC(tp, meshctl_readline_eof);
	ATF_TP_ADD_TC(tp, meshctl_exchange_truncated_reply);
	ATF_TP_ADD_TC(tp, meshctl_connect_failure_exits_two);
	return (atf_no_error());
}
