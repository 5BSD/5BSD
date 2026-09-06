/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <tracecmp.h>
#include "fake_service.h"

struct caller { int fd; int error; };
static void *
open_trace(void *argument)
{
	struct caller *caller = argument;
	if (tracecmp_open(&caller->fd) == -1)
		caller->error = errno;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(independent_concurrent_sessions);
ATF_TC_BODY(independent_concurrent_sessions, tc)
{
	struct caller callers[8];
	pthread_t threads[8];
	unsigned i;
	fake_service_reset();
	for (i = 0; i < 8; i++) {
		callers[i] = (struct caller){ .fd = -1 };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, open_trace,
		    &callers[i]));
	}
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, callers[i].error);
		ATF_CHECK(fcntl(callers[i].fd, F_GETFD) != -1);
		close(callers[i].fd);
	}
	ATF_CHECK_EQ(8, fake_service_created());
	ATF_CHECK_EQ(8, fake_service_closed());
	ATF_CHECK(fake_service_max_concurrent() > 1);
}

ATF_TC_WITHOUT_HEAD(discovery_and_peer_failures);
ATF_TC_BODY(discovery_and_peer_failures, tc)
{
	int fd = 42;
	fake_service_reset();
	fake_service_fail_connect(ENOENT);
	ATF_CHECK_ERRNO(ENOENT, tracecmp_open(&fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(0, fake_service_created());
	fake_service_fail_call(ECONNRESET);
	ATF_CHECK_ERRNO(ECONNRESET, tracecmp_open(&fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	ATF_CHECK_EQ(1, fake_service_created());
	ATF_CHECK_EQ(1, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(feature_and_attachment_validation);
ATF_TC_BODY(feature_and_attachment_validation, tc)
{
	int fd;
	fake_service_reset();
	fake_service_reply_mode(FAKE_REPLY_NO_FEATURE);
	ATF_CHECK_ERRNO(EOPNOTSUPP, tracecmp_open(&fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fake_service_reply_mode(FAKE_REPLY_BAD_OPCODE);
	ATF_CHECK_ERRNO(EPROTO, tracecmp_open(&fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fake_service_reply_mode(FAKE_REPLY_MISSING_FD);
	ATF_CHECK_ERRNO(EPROTO, tracecmp_open(&fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fake_service_reply_mode(FAKE_REPLY_UNEXPECTED_HELLO_FD);
	ATF_CHECK_ERRNO(EPROTO, tracecmp_open(&fd) == -1);
	ATF_CHECK_EQ(-1, fd);
	fake_service_reply_mode(FAKE_REPLY_BAD_MAGIC);
	ATF_CHECK_ERRNO(EPROTO, tracecmp_open(&fd) == -1);
	fake_service_reply_mode(FAKE_REPLY_BAD_VERSION);
	ATF_CHECK_ERRNO(EPROTO, tracecmp_open(&fd) == -1);
	fake_service_reply_mode(FAKE_REPLY_BAD_FLAGS);
	ATF_CHECK_ERRNO(EPROTO, tracecmp_open(&fd) == -1);
	fake_service_reply_mode(FAKE_REPLY_BAD_HELLO_RESERVED);
	ATF_CHECK_ERRNO(EPROTO, tracecmp_open(&fd) == -1);
	ATF_CHECK_EQ(8, fake_service_created());
	ATF_CHECK_EQ(8, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(delegated_fd_is_not_inherited);
ATF_TC_BODY(delegated_fd_is_not_inherited, tc)
{
	int fd, status;
	pid_t pid;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, tracecmp_open(&fd));
	ATF_REQUIRE(fcntl(fd, F_GETFD) != -1);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 1);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);
	ATF_REQUIRE_EQ(0, close(fd));
}

ATF_TC_WITHOUT_HEAD(repeated_open_close);
ATF_TC_BODY(repeated_open_close, tc)
{
	int fd;
	unsigned i;
	fake_service_reset();
	for (i = 0; i < 32; i++) {
		ATF_REQUIRE_EQ(0, tracecmp_open(&fd));
		ATF_REQUIRE(fcntl(fd, F_GETFD) != -1);
		ATF_REQUIRE_EQ(0, close(fd));
	}
	ATF_CHECK_EQ(32, fake_service_created());
	ATF_CHECK_EQ(32, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(stats_reports_provider_counters);
ATF_TC_BODY(stats_reports_provider_counters, tc)
{
	struct tracecmp_stats stats;

	fake_service_reset();
	/* A STATS call opens a session, reads the counters, and closes it. */
	memset(&stats, 0xff, sizeof(stats));
	ATF_REQUIRE_EQ(0, tracecmp_stats(&stats));
	ATF_CHECK_EQ(FAKE_STATS_OPENED, stats.opened);
	ATF_CHECK_EQ(FAKE_STATS_REJECTED, stats.rejected);
	ATF_CHECK_EQ(0, stats.reserved[0]);
	ATF_CHECK_EQ(0, stats.reserved[1]);
	ATF_CHECK_EQ(1, fake_service_created());
	ATF_CHECK_EQ(1, fake_service_closed());

	/* Fails closed on a NULL out pointer, without touching the service. */
	ATF_CHECK_ERRNO(EINVAL, tracecmp_stats(NULL) == -1);
	ATF_CHECK_EQ(1, fake_service_created());

	/* Discovery and peer failures propagate. */
	fake_service_fail_connect(ENOENT);
	ATF_CHECK_ERRNO(ENOENT, tracecmp_stats(&stats) == -1);
	ATF_CHECK_EQ(1, fake_service_created());
	fake_service_fail_call(ECONNRESET);
	ATF_CHECK_ERRNO(ECONNRESET, tracecmp_stats(&stats) == -1);
	ATF_CHECK_EQ(2, fake_service_created());
	ATF_CHECK_EQ(2, fake_service_closed());
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, independent_concurrent_sessions);
	ATF_TP_ADD_TC(tp, discovery_and_peer_failures);
	ATF_TP_ADD_TC(tp, feature_and_attachment_validation);
	ATF_TP_ADD_TC(tp, delegated_fd_is_not_inherited);
	ATF_TP_ADD_TC(tp, repeated_open_close);
	ATF_TP_ADD_TC(tp, stats_reports_provider_counters);
	return (atf_no_error());
}
