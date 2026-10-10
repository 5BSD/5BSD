/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <stdbool.h>
#include <unistd.h>
static int passed_fd, session_fd, close_count;
static bool create_failure;
static int
fake_open(const char *name, int *fd)
{
	int p[2];
	(void)name;
	ATF_REQUIRE_EQ(0, pipe(p));
	close(p[1]);
	*fd = p[0];
	return (0);
}
static int
fake_limit(int fd, int state)
{
	(void)fd;
	(void)state;
	return (0);
}
static int
fake_create(int fd, struct service_session **session)
{
	passed_fd = fd;
	if (create_failure)
		return (errno = ENOMEM, -1);
	session_fd = dup(fd);
	ATF_REQUIRE(session_fd >= 0);
	*session = (void *)1;
	return (0);
}
static void
fake_close(struct service_session *session)
{
	(void)session;
	close_count++;
	close(session_fd);
}
#define service_open	       fake_open
#define service_session_create fake_create
#define service_session_close  fake_close
#define cap_xfer_limit	       fake_limit
#define cap_cloexec_limit      fake_limit
#include "../powercmp.c"
ATF_TC_WITHOUT_HEAD(constructor_releases_input);
ATF_TC_BODY(constructor_releases_input, tc)
{
	struct powercmp_client *client;
	ATF_REQUIRE_EQ(0, powercmp_client_open(&client));
	ATF_CHECK_ERRNO(EBADF, fcntl(passed_fd, F_GETFD) == -1);
	ATF_CHECK(fcntl(session_fd, F_GETFD) != -1);
	powercmp_client_close(client);
	ATF_CHECK_EQ(1, close_count);
	ATF_CHECK_ERRNO(EBADF, fcntl(session_fd, F_GETFD) == -1);
}
ATF_TC_WITHOUT_HEAD(constructor_failure_closes_input);
ATF_TC_BODY(constructor_failure_closes_input, tc)
{
	struct powercmp_client *client = (void *)1;
	create_failure = true;
	ATF_CHECK_ERRNO(ENOMEM, powercmp_client_open(&client) == -1);
	ATF_CHECK(client == NULL);
	ATF_CHECK_ERRNO(EBADF, fcntl(passed_fd, F_GETFD) == -1);
	ATF_CHECK_EQ(0, close_count);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, constructor_releases_input);
	ATF_TP_ADD_TC(tp, constructor_failure_closes_input);
	return (atf_no_error());
}
