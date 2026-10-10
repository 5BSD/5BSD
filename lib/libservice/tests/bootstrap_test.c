/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

static int fragment, reads, writes;
static ssize_t
injected_recv(int fd, void *buffer, size_t length, int flags)
{
	ATF_CHECK((flags & MSG_DONTWAIT) != 0);
	if (fragment && ++reads == 1)
		return (errno = EINTR, -1);
	return (recv(fd, buffer, fragment ? 1 : length, flags));
}
static ssize_t
injected_send(int fd, const void *buffer, size_t length, int flags)
{
	ATF_CHECK((flags & MSG_NOSIGNAL) != 0);
	ATF_CHECK((flags & MSG_DONTWAIT) != 0);
	if (fragment && ++writes == 1)
		return (errno = EINTR, -1);
	return (send(fd, buffer, length, flags));
}
#define recv injected_recv
#define send injected_send
#include "../service_runtime.c"
#undef recv
#undef send
ATF_TC_WITHOUT_HEAD(bootstrap_socket_errors);
ATF_TC_BODY(bootstrap_socket_errors, tc)
{
	int pair[2], child_error, expected;
	char byte;

	for (int mode = 0; mode < 6; mode++) {
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
		fragment = mode == 1;
		reads = writes = 0;
		child_error = mode == 2 ? EACCES : mode == 3 ? -1 : 0;
		ATF_REQUIRE_EQ(mode == 4 ? 1 : sizeof(child_error),
		    write(pair[1], &child_error, mode == 4 ? 1 : sizeof(child_error)));
		if (mode >= 4) {
			close(pair[1]);
			pair[1] = -1;
		}
		expected = mode == 2 ? EACCES : mode == 3 ? EPROTO :
		    mode == 4 ? EIO : mode == 5 ? EPIPE : 0;
		if (expected != 0)
			ATF_CHECK_ERRNO(expected, service_bootstrap_parent(pair[0], 5000) == -1);
		else {
			ATF_REQUIRE_EQ(0, service_bootstrap_parent(pair[0], 5000));
			ATF_REQUIRE_EQ(1, read(pair[1], &byte, 1));
			ATF_CHECK_EQ(1, byte);
		}
		if (fragment) {
			ATF_CHECK_EQ(1 + sizeof(child_error), reads);
			ATF_CHECK_EQ(2, writes);
		}
		close(pair[0]);
		if (pair[1] >= 0)
			close(pair[1]);
	}
}
ATF_TC_WITHOUT_HEAD(bootstrap_stall_deadline);
ATF_TC_BODY(bootstrap_stall_deadline, tc)
{
	int pair[2];
	uint64_t start, elapsed;
	char byte = 0, fill[4096] = { 0 };
	int child_error = 0;
	ssize_t n;

	for (int partial = 0; partial < 3; partial++) {
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
		if (partial == 1)
			ATF_REQUIRE_EQ(1, write(pair[1], &byte, 1));
		if (partial == 2) {
			ATF_REQUIRE_EQ(sizeof(child_error),
			    write(pair[1], &child_error, sizeof(child_error)));
			do {
				n = send(pair[0], fill, sizeof(fill),
				    MSG_DONTWAIT | MSG_NOSIGNAL);
			} while (n > 0);
			ATF_REQUIRE_ERRNO(EAGAIN, n == -1);
		}
		start = service_monotime_ms();
		ATF_CHECK_ERRNO(ETIMEDOUT, service_bootstrap_parent(pair[0], 5000) == -1);
		elapsed = service_monotime_ms() - start;
		ATF_CHECK(elapsed >= 5000);
		ATF_CHECK_MSG(elapsed < 8000, "bootstrap took %ju ms",
		    (uintmax_t)elapsed);
		ATF_CHECK_EQ(0, fcntl(pair[0], F_GETFL) & O_NONBLOCK);
		close(pair[0]);
		close(pair[1]);
	}
}

ATF_TC_WITHOUT_HEAD(bootstrap_invalid_arguments);
ATF_TC_BODY(bootstrap_invalid_arguments, tc)
{
	ATF_CHECK_ERRNO(EINVAL, service_bootstrap_parent(-1, 1) == -1);
	ATF_CHECK_ERRNO(EINVAL, service_bootstrap_parent(0, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL, service_bootstrap_parent(0, UINT32_MAX) == -1);
}
ATF_TC_WITHOUT_HEAD(bootstrap_seqpacket);
ATF_TC_BODY(bootstrap_seqpacket, tc)
{
	int pair[2], child_error;
	char release;

	/* BSDLog's pool control is record-oriented, unlike audit/network. */
	fragment = 0;
	for (int failure = 0; failure < 2; failure++) {
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
		child_error = failure ? EACCES : 0;
		ATF_REQUIRE_EQ(sizeof(child_error),
		    write(pair[1], &child_error, sizeof(child_error)));
		if (failure)
			ATF_CHECK_ERRNO(EACCES,
			    service_bootstrap_parent(pair[0], 5000) == -1);
		else {
			ATF_REQUIRE_EQ(0, service_bootstrap_parent(pair[0], 5000));
			ATF_REQUIRE_EQ(1, read(pair[1], &release, sizeof(release)));
			ATF_CHECK_EQ(1, release);
		}
		close(pair[0]);
		close(pair[1]);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bootstrap_socket_errors);
	ATF_TP_ADD_TC(tp, bootstrap_stall_deadline);
	ATF_TP_ADD_TC(tp, bootstrap_invalid_arguments);
	ATF_TP_ADD_TC(tp, bootstrap_seqpacket);
	return (atf_no_error());
}
