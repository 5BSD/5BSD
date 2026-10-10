/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <libservice.h>

static int worker_mode, accepts, backup_pd, worker_pd, idle_declines;
static pid_t child_pid;
static void assert_windows(bool);
static int step, fail_step, queue_fd, destroyed, acknowledged, test_ready;
static int
check_step(void)
{
	return (++step == fail_step ? (errno = EIO, -1) : 0);
}
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
	if (nc != 0 && changes[0].filter == EVFILT_PROCDESC &&
	    (worker_mode == 1 || worker_mode == 2))
		return (errno = ENOSPC, -1);
	if (nc == 0) {
		event->filter = EVFILT_READ;
		return (1);
	}
	return (0);
}
static int
fake_accept(struct service_listener *l, struct service_identity *id, int *fd)
{
	(void)l;
	(void)check_step();
	if (worker_mode != 0 && accepts++ == 0) {
		strlcpy(id->resource_owner, "org.test.lifecycle", sizeof(id->resource_owner));
		*fd = open("/dev/null", O_RDONLY);
		ATF_REQUIRE(*fd >= 0);
		return (0);
	}
	return (errno = EIO, -1);
}
static pid_t
fake_fork(int *pd, int flags)
{
	pid_t pid;

	pid = pdfork(pd, flags);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		for (;;)
			pause();
	child_pid = pid;
	worker_pd = *pd;
	backup_pd = dup(*pd);
	ATF_REQUIRE(backup_pd >= 0);
	return (pid);
}
static int
fake_kill(int pd, int sig)
{
	if (worker_mode == 2)
		return (errno = EPERM, -1);
	return (pdkill(pd, sig));
}
static int fake_quiescing(struct service_provider *p)
{ (void)p; return (worker_mode != 0 || fail_step == 0 || fail_step == 11); }
static int
fake_complete(struct service_provider *p, int status)
{
	(void)p;
	if (status == EBUSY) {
		assert_windows(true);
		if (worker_mode == 4 && idle_declines++ == 0)
			return (0);
		return (errno = EINVAL, -1);
	}
	ATF_CHECK_EQ(0, status);
	if (worker_mode != 0)
		assert_windows(false);
	ATF_CHECK_EQ(1, test_ready);
	ATF_CHECK_ERRNO(EBADF, fcntl(queue_fd, F_GETFD) == -1);
	acknowledged++;
	return (fail_step == 11 ? (errno = EIO, -1) : 0);
}
static void fake_destroy(struct service_provider *p)
{ (void)p; destroyed++; }
#define pdfork fake_fork
#define pdkill fake_kill
#define kqueuex fake_queue
#define service_provider_create fake_create
#define service_provider_authorize_capabilities fake_authorize
#define service_provider_protect fake_protect
#define service_provider_expose fake_expose
#define service_listener_fd fake_fd
#define service_provider_enter_ambient fake_enter
#define service_provider_ready fake_ready
#define kevent(...) fake_event(__VA_ARGS__)
#define service_listener_accept fake_accept
#define service_provider_quiescing fake_quiescing
#define service_provider_quiesce_complete fake_complete
#define service_provider_destroy fake_destroy
int bsdvm_main(int, char **);
#undef VMD_TESTING
#define main bsdvm_main
#include "../bsdvm.c"
#undef main

static void
assert_windows(bool used)
{
	unsigned refs = 0;

	for (size_t i = 0; i < nitems(g_windows); i++)
		if (g_windows[i].used)
			refs += g_windows[i].refs;
	ATF_CHECK_EQ(used ? 1 : 0, refs);
}

ATF_TC_WITHOUT_HEAD(lifecycle_failures);
ATF_TC_BODY(lifecycle_failures, tc)
{
	for (fail_step = 0; fail_step <= 11; fail_step++) {
		step = destroyed = acknowledged = test_ready = 0;
		queue_fd = -1;
		ATF_CHECK_EQ(fail_step == 0 ? 0 : -1, vmd_serve());
		ATF_CHECK_EQ(fail_step == 1 ? 0 : 1, destroyed);
		ATF_CHECK_EQ(fail_step == 0 || fail_step == 11 ? 1 : 0, acknowledged);
		if (queue_fd != -1)
			ATF_CHECK_ERRNO(EBADF, fcntl(queue_fd, F_GETFD) == -1);
	}
}
ATF_TC_WITHOUT_HEAD(worker_loop_cleanup);
ATF_TC_BODY(worker_loop_cleanup, tc)
{
	int result, status;

	for (int scenario = 1; scenario <= 4; scenario++) {
		worker_mode = scenario;
		fail_step = 0;
		step = destroyed = acknowledged = test_ready = accepts = idle_declines = 0;
		queue_fd = backup_pd = worker_pd = -1;
		memset(g_windows, 0, sizeof(g_windows));
		result = vmd_serve();
		ATF_CHECK_EQ(scenario == 2 ? -1 : 0, result);
		ATF_CHECK_EQ(1, destroyed);
		ATF_CHECK_EQ(scenario == 2 ? 0 : 1, acknowledged);
		ATF_CHECK_ERRNO(EBADF, fcntl(queue_fd, F_GETFD) == -1);
		ATF_CHECK_ERRNO(EBADF, fcntl(worker_pd, F_GETFD) == -1);
		assert_windows(scenario == 2);
		ATF_REQUIRE(backup_pd >= 0);
		if (scenario == 2) {
			/* The injected denial left the child alive; fixture owns recovery. */
			worker_mode = 0;
			ATF_REQUIRE_EQ(0, pdkill(backup_pd, SIGKILL));
			ATF_REQUIRE(pdwait(backup_pd, &status, WEXITED, NULL, NULL) != -1);
		} else
			ATF_CHECK_ERRNO(ECHILD, waitpid(child_pid, &status, WNOHANG) == -1);
		close(backup_pd);
		if (scenario == 4)
			ATF_CHECK_EQ(2, idle_declines);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lifecycle_failures);
	ATF_TP_ADD_TC(tp, worker_loop_cleanup);
	return (atf_no_error());
}
