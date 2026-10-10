/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <liboes.h>
#include <stdarg.h>
#include <string.h>
static int calls;
static unsigned long captured_command;
static struct oes_mute_path_args captured;
static int
fake_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	(void)fd;
	va_start(ap, request);
	captured = *va_arg(ap, struct oes_mute_path_args *);
	va_end(ap);
	captured_command = request;
	calls++;
	return (0);
}
#define ioctl fake_ioctl
#include "../liboes.c"
#undef ioctl
ATF_TC_WITHOUT_HEAD(path_boundaries);
ATF_TC_BODY(path_boundaries, tc)
{
	int (*functions[])(oes_client_t *, const char *,
	    uint32_t) = { oes_mute_path, oes_unmute_path, oes_mute_target_path,
		oes_unmute_target_path };
	char path[sizeof(captured.emp_path) + 1];
	oes_client_t *client = oes_client_create_from_fd(10);
	ATF_REQUIRE(client != NULL);
	for (unsigned i = 0; i < 4; i++) {
		calls = 0;
		ATF_CHECK_ERRNO(EINVAL,
		    functions[i](client, NULL, OES_MUTE_PATH_LITERAL) == -1);
		ATF_CHECK_ERRNO(EINVAL,
		    functions[i](client, "", OES_MUTE_PATH_LITERAL) == -1);
		memset(path, 'a', sizeof(path));
		path[sizeof(path) - 1] = '\0';
		ATF_CHECK_ERRNO(ENAMETOOLONG,
		    functions[i](client, path, OES_MUTE_PATH_PREFIX) == -1);
		ATF_CHECK_EQ(0, calls);
		path[sizeof(path) - 2] = '\0';
		ATF_CHECK_EQ(0,
		    functions[i](client, path, OES_MUTE_PATH_PREFIX));
		ATF_CHECK_EQ(1, calls);
		ATF_CHECK_STREQ(path, captured.emp_path);
		ATF_CHECK_EQ(OES_MUTE_PATH_PREFIX, captured.emp_type);
		ATF_CHECK_EQ(i >= 2 ? OES_MUTE_PATH_FLAG_TARGET : 0,
		    captured.emp_flags);
		ATF_CHECK_EQ(i % 2 ? OES_IOC_UNMUTE_PATH : OES_IOC_MUTE_PATH,
		    captured_command);
	}
	oes_client_destroy(client);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, path_boundaries);
	return (atf_no_error());
}
