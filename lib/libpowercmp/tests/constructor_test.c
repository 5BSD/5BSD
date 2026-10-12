/* SPDX-License-Identifier: BSD-2-Clause */
/* powercmp_client_open() descriptor ownership, with service_open faked. */
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <stdbool.h>
#include <unistd.h>
static int passed_fd = -1;
static int
fake_open(const char *name, int *fd)
{
	int p[2];
	(void)name;
	ATF_REQUIRE_EQ(0, pipe(p));
	close(p[1]);
	*fd = passed_fd = p[0];
	return (0);
}
#define service_open fake_open
#include "../powercmp.c"

/* A descriptor that is not a capability channel cannot become a session;
 * open() must not leak it and must leave the result NULL. */
ATF_TC_WITHOUT_HEAD(constructor_failure_closes_input);
ATF_TC_BODY(constructor_failure_closes_input, tc)
{
	struct powercmp_client *client = (void *)1;
	ATF_CHECK_EQ(-1, powercmp_client_open(&client));
	ATF_CHECK(client == NULL);
	ATF_CHECK_ERRNO(EBADF, fcntl(passed_fd, F_GETFD) == -1);
}
ATF_TC_WITHOUT_HEAD(null_arguments);
ATF_TC_BODY(null_arguments, tc)
{
	uint32_t value;
	ATF_CHECK_ERRNO(EINVAL, powercmp_client_open(NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, powercmp_client_create(0, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, powercmp_states(NULL, &value) == -1);
	ATF_CHECK_ERRNO(EINVAL, powercmp_inhibitors(NULL, &value) == -1);
	ATF_CHECK_ERRNO(EINVAL, powercmp_suspend(NULL, 9) == -1);
	powercmp_client_close(NULL);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, constructor_failure_closes_input);
	ATF_TP_ADD_TC(tp, null_arguments);
	return (atf_no_error());
}
