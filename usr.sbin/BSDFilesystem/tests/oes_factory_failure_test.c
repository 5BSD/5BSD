/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <security/oes/oes.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
static int fail_at, step, created_fd;
static int
failpoint(void)
{
	step++;
	return (step == fail_at ? (errno = EIO, -1) : 0);
}
static int
fake_openat(int dir, const char *path, int flags, ...)
{
	int p[2];
	(void)dir;
	ATF_CHECK_STREQ("dev/oes", path);
	ATF_CHECK(
	    (flags &
		(O_NOFOLLOW | O_RESOLVE_BENEATH | O_CLOEXEC | O_NONBLOCK)) ==
	    (O_NOFOLLOW | O_RESOLVE_BENEATH | O_CLOEXEC | O_NONBLOCK));
	if (failpoint() == -1)
		return (-1);
	ATF_REQUIRE_EQ(0, pipe(p));
	close(p[1]);
	return (created_fd = p[0]);
}
static int
fake_ioctl(int fd, unsigned long cmd, ...)
{
	va_list ap;
	(void)fd;
	if (failpoint() == -1)
		return (-1);
	va_start(ap, cmd);
	if (cmd == OES_IOC_GET_MODE) {
		struct oes_mode_args *arg = va_arg(ap, struct oes_mode_args *);
		arg->ema_mode = fail_at == 7 ? OES_MODE_AUTH : OES_MODE_NOTIFY;
	} else {
		ATF_CHECK_EQ(OES_IOC_GET_SCOPE, cmd);
		struct oes_scope_args *arg = va_arg(ap,
		    struct oes_scope_args *);
		arg->esa_scope = fail_at == 8 ? OES_SCOPE_DESCENDANTS :
						OES_SCOPE_GLOBAL;
	}
	va_end(ap);
	return (0);
}
static int
fake_rights(int fd, const cap_rights_t *rights)
{
	(void)fd;
	ATF_CHECK(!cap_rights_is_set(rights, CAP_WRITE));
	return (failpoint());
}
static int
fake_ioctls(int fd, const cap_ioctl_t *commands, size_t count)
{
	(void)fd;
	ATF_CHECK_EQ(6, count);
	for (size_t i = 0; i < count; i++) {
		ATF_CHECK(commands[i] != OES_IOC_SET_MODE);
		ATF_CHECK(commands[i] != OES_IOC_SET_SCOPE);
	}
	return (failpoint());
}
static int
fake_harden(int fd, unsigned flags)
{
	(void)fd;
	ATF_CHECK_EQ(SERVICE_HARDEN_XFER_ONCE, flags);
	return (failpoint());
}
#define openat		  fake_openat
#define ioctl		  fake_ioctl
#define cap_rights_limit  fake_rights
#define cap_ioctls_limit  fake_ioctls
#define service_harden_fd fake_harden
#include "../oes_factory.c"
ATF_TC_WITHOUT_HEAD(factory_failure_cleanup);
ATF_TC_BODY(factory_failure_cleanup, tc)
{
	for (fail_at = 1; fail_at <= 8; fail_at++) {
		step = 0;
		created_fd = -1;
		ATF_CHECK_EQ(-1, bsdfilesystem_oes_open_notify(10));
		ATF_CHECK_EQ(fail_at >= 7 ? EPROTO : EIO, errno);
		if (created_fd >= 0)
			ATF_CHECK_ERRNO(EBADF,
			    fcntl(created_fd, F_GETFD) == -1);
	}
}
ATF_TC_WITHOUT_HEAD(factory_success_retains_one_descriptor);
ATF_TC_BODY(factory_success_retains_one_descriptor, tc)
{
	int fd = bsdfilesystem_oes_open_notify(10);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(6, step);
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);
	close(fd);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, factory_failure_cleanup);
	ATF_TP_ADD_TC(tp, factory_success_retains_one_descriptor);
	return (atf_no_error());
}
