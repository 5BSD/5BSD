/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The socket commands of dq_oracle_test: socket(2) and socketpair(2) of a
 * few kinds, printed so that a run under dqpass can be compared with an
 * unattached one.
 */

#include <sys/socket.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
report(const char *what, int rv)
{

	if (rv == -1)
		printf("%s: %s\n", what, strerror(errno));
	else
		printf("%s: ok\n", what);
}

int
main(void)
{
	char buf[4];
	int s, sv[2], rv;

	s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	report("socket inet stream", s);
	if (s != -1)
		(void)close(s);
	s = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	report("socket inet dgram", s);
	if (s != -1)
		(void)close(s);
	s = socket(AF_UNIX, SOCK_DGRAM, 0);
	report("socket unix dgram", s);
	if (s != -1)
		(void)close(s);
	report("socket unix raw", socket(AF_UNIX, SOCK_RAW, 0));
	rv = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	report("socketpair unix stream", rv);
	if (rv == 0) {
		rv = write(sv[0], "abc", 3) == 3 && read(sv[1], buf, 3) == 3 &&
		    memcmp(buf, "abc", 3) == 0 ? 0 : -1;
		report("socketpair transfer", rv);
		(void)close(sv[0]);
		(void)close(sv[1]);
	}
	report("socketpair inet stream", socketpair(AF_INET, SOCK_STREAM, 0,
	    sv));
	return (0);
}
