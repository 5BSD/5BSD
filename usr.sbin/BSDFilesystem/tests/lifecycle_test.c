/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>

static bool busy_case;
static int accepts, watches, busy_acks, success_acks, destroyed, child_pd;
static pid_t child_pid;
static struct service_listener *test_listener = (void *)(uintptr_t)2;

static int test_create(struct service_provider **p)
{ *p = (void *)(uintptr_t)1; return (0); }
static int test_setup(struct service_provider *p __unused) { return (0); }
static int
test_expose(struct service_provider *p __unused, const char *name __unused,
    struct service_listener **listener)
{ *listener = test_listener; return (0); }
static int test_listener_fd(const struct service_listener *l __unused) { return (42); }
static int
test_accept(struct service_listener *l __unused, struct service_identity *id, int *fd)
{
	if (busy_case && accepts++ == 0) {
		strlcpy(id->client_label, "org.test.filesystem", sizeof(id->client_label));
		*fd = open("/dev/null", O_RDONLY);
		return (*fd == -1 ? -1 : 0);
	}
	return (errno = ECANCELED, -1);
}
static int test_quiescing(struct service_provider *p __unused) { return (1); }
static int
test_complete(struct service_provider *p __unused, int error)
{
	if (error == EBUSY) {
		busy_acks++;
		ATF_REQUIRE_EQ(0, pdkill(child_pd, 0));
	} else {
		ATF_REQUIRE_EQ(0, error);
		success_acks++;
	}
	return (0);
}
static void
test_destroy(struct service_provider *p __unused)
{
	int status;

	destroyed++;
	if (busy_case) {
		ATF_CHECK_ERRNO(EBADF, fcntl(child_pd, F_GETFD) == -1);
		ATF_CHECK_ERRNO(ECHILD, waitpid(child_pid, &status, WNOHANG) == -1);
	}
}
static pid_t
test_pdfork(int *pd, int flags)
{
	pid_t pid = pdfork(pd, flags);

	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		for (;;)
			pause();
	child_pd = *pd;
	child_pid = pid;
	return (pid);
}
static int
test_kevent(int kq __unused, const struct kevent *changes __unused, int nc,
    struct kevent *event, int ne __unused, const struct timespec *timeout __unused)
{
	if (nc != 0)
		return (0);
	if (watches++ >= (busy_case ? 2 : 1))
		return (errno = EIO, -1);
	EV_SET(event, 42, EVFILT_READ, 0, 0, 0, test_listener);
	return (1);
}
#define service_provider_create test_create
#define service_provider_authorize_capabilities test_setup
#define service_provider_enter_capability_mode test_setup
#define service_provider_ready test_setup
#define service_provider_expose test_expose
#define service_listener_fd test_listener_fd
#define service_listener_accept test_accept
#define service_provider_quiescing test_quiescing
#define service_provider_quiesce_complete test_complete
#define service_provider_destroy test_destroy
#define pdfork test_pdfork
#define kevent(...) test_kevent(__VA_ARGS__)
#include "../request.c"
#undef kevent
#undef pdfork

ATF_TC_WITHOUT_HEAD(quiesce_ownership);
ATF_TC_BODY(quiesce_ownership, tc)
{
	struct bsdfilesystem_state state;
	int result;

	for (unsigned pass = 0; pass < 2; pass++) {
		busy_case = pass != 0;
		accepts = watches = busy_acks = success_acks = destroyed = 0;
		memset(&state, 0, sizeof(state));
		result = bsdfilesystem_serve(&state);
		ATF_CHECK_EQ(busy_case ? -1 : 0, result);
		ATF_CHECK_EQ(busy_case ? 1 : 0, busy_acks);
		ATF_CHECK_EQ(busy_case ? 0 : 1, success_acks);
		ATF_CHECK_EQ(1, destroyed);
	}
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, quiesce_ownership);
	return (atf_no_error());
}
