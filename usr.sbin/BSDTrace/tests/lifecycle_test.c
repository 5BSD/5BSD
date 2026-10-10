/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/event.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <libservice.h>

static int step, fail_step, queue_fd, destroyed, acknowledged, test_ready;
static int
check_step(void)
{
	return (++step == fail_step ? (errno = EIO, -1) : 0);
}
static void fake_title(void) {}
static int fake_config(const char *name, int *fd)
{ (void)name; (void)fd; return (errno = ENOENT, -1); }
static int fake_resource(const char *name, int *fd)
{ (void)name; (void)fd; return (errno = ENOENT, -1); }
static int
fake_queue(unsigned flags)
{
	(void)flags;
	if (check_step() == -1)
		return (-1);
	queue_fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(queue_fd >= 0);
	return (queue_fd);
}
static int
fake_create(struct service_provider **p)
{
	if (check_step() == -1)
		return (-1);
	*p = (void *)(uintptr_t)1;
	return (0);
}
static int fake_authorize(struct service_provider *p) { (void)p; return (check_step()); }
static int fake_protect(struct service_provider *p, uint32_t flags)
{ (void)p; (void)flags; return (check_step()); }
static int
fake_expose(struct service_provider *p, const char *name, struct service_listener **l)
{
	(void)p; (void)name;
	if (check_step() == -1)
		return (-1);
	*l = (void *)(uintptr_t)2;
	return (0);
}
static int fake_fd(const struct service_listener *l) { (void)l; return (10); }
static int fake_enter(struct service_provider *p) { (void)p; return (check_step()); }
static int fake_ready(struct service_provider *p)
{ (void)p; if (check_step() == -1) return (-1); test_ready = 1; return (0); }
static int
fake_event(int kq, const struct kevent *changes, int nc, struct kevent *event,
    int ne, const struct timespec *timeout)
{
	(void)kq; (void)changes; (void)ne; (void)timeout;
	if (check_step() == -1)
		return (-1);
	if (nc == 0) {
		event->filter = EVFILT_READ;
		return (1);
	}
	return (0);
}
static int fake_accept(struct service_listener *l, struct service_identity *id, int *fd)
{ (void)l; (void)id; (void)fd; (void)check_step(); return (errno = EIO, -1); }
static int fake_quiescing(struct service_provider *p)
{ (void)p; return (fail_step == 0 || fail_step == 11); }
static int
fake_complete(struct service_provider *p, int status)
{
	(void)p;
	ATF_CHECK_EQ(0, status);
	ATF_CHECK_EQ(1, test_ready);
	ATF_CHECK_ERRNO(EBADF, fcntl(queue_fd, F_GETFD) == -1);
	acknowledged++;
	return (fail_step == 11 ? (errno = EIO, -1) : 0);
}
static void fake_destroy(struct service_provider *p)
{ (void)p; destroyed++; }
#define service_config_open fake_config
#define service_resource_dir fake_resource
#define service_set_proctitle fake_title
#define kqueuex fake_queue
#define service_provider_create fake_create
#define service_provider_authorize_capabilities fake_authorize
#define service_provider_protect fake_protect
#define service_provider_expose fake_expose
#define service_listener_fd fake_fd
#define service_provider_enter_capability_mode fake_enter
#define service_provider_ready fake_ready
#define kevent(...) fake_event(__VA_ARGS__)
#define service_listener_accept fake_accept
#define service_provider_quiescing fake_quiescing
#define service_provider_quiesce_complete fake_complete
#define service_provider_destroy fake_destroy
int bsdtrace_main(void);
#define main bsdtrace_main
#include "../tracecmp.c"
#undef main

ATF_TC_WITHOUT_HEAD(lifecycle_failures);
ATF_TC_BODY(lifecycle_failures, tc)
{
	for (fail_step = 0; fail_step <= 11; fail_step++) {
		step = destroyed = acknowledged = test_ready = 0;
		queue_fd = -1;
		ATF_CHECK_EQ(fail_step == 0 ? 0 : 1, bsdtrace_main());
		ATF_CHECK_EQ(fail_step == 1 || fail_step == 2 ? 0 : 1, destroyed);
		ATF_CHECK_EQ(fail_step == 0 || fail_step == 11 ? 1 : 0, acknowledged);
		if (queue_fd != -1)
			ATF_CHECK_ERRNO(EBADF, fcntl(queue_fd, F_GETFD) == -1);
	}
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lifecycle_failures);
	return (atf_no_error());
}
