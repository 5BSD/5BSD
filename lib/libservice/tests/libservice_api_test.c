/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <atf-c.h>
#include <libservice.h>

ATF_TC(authorize_capabilities_environment);
ATF_TC_HEAD(authorize_capabilities_environment, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "capability activation accepts an empty environment and rejects malformed fd lists");
}
ATF_TC_BODY(authorize_capabilities_environment, tc)
{
	(void)tc;

	ATF_REQUIRE(unsetenv("ORACLED_TOKEN_FDS") == 0);
	ATF_CHECK_EQ(service_authorize_capabilities(), 0);
	ATF_REQUIRE(setenv("ORACLED_TOKEN_FDS", "0,,1", 1) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_authorize_capabilities() == -1);
	ATF_REQUIRE(setenv("ORACLED_TOKEN_FDS", "not-a-fd", 1) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_authorize_capabilities() == -1);
}

ATF_TC(api_rejects_invalid_descriptors_and_arguments);
ATF_TC_HEAD(api_rejects_invalid_descriptors_and_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "libservice validates descriptor types, arguments, and payload sizes");
}
ATF_TC_BODY(api_rejects_invalid_descriptors_and_arguments, tc)
{
	char value[32];
	int fd;

	(void)tc;
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)snprintf(value, sizeof(value), "%d", fd);
	ATF_REQUIRE(setenv("ORACLED_CHANNEL_FD", value, 1) == 0);
	ATF_REQUIRE(unsetenv("ORACLED_CAPPROTECT_FD") == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_init() == -1);
	ATF_REQUIRE(setenv("ORACLED_CHANNEL_FD", "2147483647", 1) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_init() == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_register(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_unregister(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_lookup(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_send(-1, NULL, 1) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, service_recv(-1, NULL, 1, NULL) == -1);
#if SIZE_MAX > UINT32_MAX
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    service_send(-1, "", (size_t)UINT32_MAX + 1) == -1);
#endif
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, authorize_capabilities_environment);
	ATF_TP_ADD_TC(tp, api_rejects_invalid_descriptors_and_arguments);
	return (atf_no_error());
}
