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

/* EOF without a newline returns the bytes read so far, NUL-terminated. */
ATF_TC_WITHOUT_HEAD(meshctl_readline_eof);
ATF_TC_BODY(meshctl_readline_eof, tc)
{
	char buf[MESHCTL_REPLY_MAX];
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	stage_reply(sp[1], "OK partial", 10);

	ATF_REQUIRE_EQ(10, meshctl_readline(sp[0], buf, sizeof(buf)));
	ATF_CHECK_EQ(0, strcmp(buf, "OK partial"));
	close(sp[0]);
	close(sp[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, meshctl_readline_max_reply);
	ATF_TP_ADD_TC(tp, meshctl_readline_overlong_reply);
	ATF_TP_ADD_TC(tp, meshctl_readline_eof);
	return (atf_no_error());
}
