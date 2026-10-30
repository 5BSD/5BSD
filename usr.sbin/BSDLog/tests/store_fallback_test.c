/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#define service_storage_open mock_storage_open
#define service_capability_open mock_capability_open
#define main unused_daemon_main
int unused_daemon_main(void);
#include "../logcmp.c"
#undef main

static int persistent_error, fallback_error, fallback_calls;
int
mock_storage_open(struct service_context *ctx, const char *name, int *fd)
{
	(void)ctx;
	if (strcmp(name, "state") != 0)
		return (errno = EINVAL, -1);
	*fd = -1;
	if (persistent_error != 0)
		return (errno = persistent_error, -1);
	*fd = 101;
	return (0);
}
int
mock_capability_open(struct service_context *ctx, const char *name,
    const char *type, int *fd)
{
	(void)ctx;
	fallback_calls++;
	if (strcmp(name, "container") != 0 || strcmp(type, "directory") != 0)
		return (errno = EINVAL, -1);
	if (fallback_error != 0)
		return (errno = fallback_error, -1);
	*fd = 102;
	return (0);
}
ATF_TC_WITHOUT_HEAD(storage_failure_policy);
ATF_TC_BODY(storage_failure_policy, tc)
{
	const int errors[] = { EACCES, EPERM, EIO, ENOSPC, EDQUOT,
	    EPROTO, ENOENT, ENOTCAPABLE, ECONNRESET, ETIMEDOUT };
	int fd, result;

	(void)tc;
	ATF_REQUIRE_EQ(bsdlog_open_store(NULL, &fd), 0);
	ATF_REQUIRE_EQ(fd, 101);
	ATF_REQUIRE_EQ(fallback_calls, 0);
	for (size_t i = 0; i < nitems(errors); i++) {
		persistent_error = errors[i];
		result = bsdlog_open_store(NULL, &fd);
		ATF_REQUIRE_MSG(result == -1 && errno == errors[i],
		    "storage error %d must be preserved (result=%d errno=%d)",
		    errors[i], result, errno);
		ATF_REQUIRE_EQ(fallback_calls, 0);
	}
	persistent_error = ENXIO;
	ATF_REQUIRE_EQ(bsdlog_open_store(NULL, &fd), 0);
	ATF_REQUIRE_EQ(fd, 102);
	ATF_REQUIRE_EQ(fallback_calls, 1);
	fallback_error = EACCES;
	ATF_REQUIRE_ERRNO(EACCES, bsdlog_open_store(NULL, &fd) == -1);
	ATF_REQUIRE_EQ(fallback_calls, 2);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, storage_failure_policy);
	return (atf_no_error());
}
