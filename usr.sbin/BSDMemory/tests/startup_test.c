/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <fcntl.h>
int bsdmemory_test_main(void);
#define main bsdmemory_test_main
#include "../BSDMemory.c"
#undef main

struct service_provider { int unused; };
static struct service_provider fake_provider;
static unsigned fail_step, step, ready_calls, destroyed, completed;
static int queue_fd = -1;
static bool armed;
void __wrap_service_set_proctitle(void);
int __wrap_service_provider_create(struct service_provider **);
void __wrap_service_provider_destroy(struct service_provider *);
int __wrap_service_provider_authorize_capabilities(struct service_provider *);
int __wrap_service_provider_protect(struct service_provider *, uint32_t);
int __wrap_service_provider_enter_capability_mode(struct service_provider *);
int __wrap_service_provider_ready(struct service_provider *);
int __wrap_service_provider_quiescing(struct service_provider *);
int __wrap_service_provider_quiesce_complete(struct service_provider *, int);
int __wrap_kqueue(void);
int __wrap_kevent(int, const struct kevent *, int, struct kevent *, int,
    const struct timespec *);

static int
operation(void)
{
	return (++step == fail_step ? (errno = ENOMEM, -1) : 0);
}
void
__wrap_service_set_proctitle(void)
{
}
int
__wrap_service_provider_create(struct service_provider **out)
{
	int result = operation();
	*out = result == 0 ? &fake_provider : NULL;
	return (result);
}
void
__wrap_service_provider_destroy(struct service_provider *provider)
{
	ATF_REQUIRE(provider == &fake_provider);
	destroyed++;
}
int
__wrap_service_provider_authorize_capabilities(struct service_provider *provider)
{
	ATF_REQUIRE(provider == &fake_provider);
	return (operation());
}
int
__wrap_service_provider_protect(struct service_provider *provider, uint32_t flags)
{
	ATF_REQUIRE(provider == &fake_provider);
	ATF_CHECK_EQ(SERVICE_PROTECT_EXTERNAL | SERVICE_PROTECT_NOPRIVS |
	    SERVICE_PROTECT_NOEXEC, flags);
	return (operation());
}
int
__wrap_service_provider_enter_capability_mode(struct service_provider *provider)
{
	ATF_REQUIRE(provider == &fake_provider);
	return (operation());
}
int
__wrap_kqueue(void)
{
	if (operation() == -1)
		return (-1);
	queue_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(queue_fd >= 0);
	return (queue_fd);
}
int
__wrap_kevent(int fd, const struct kevent *changes, int nchanges,
    struct kevent *events, int nevents, const struct timespec *timeout)
{
	ATF_REQUIRE_EQ(queue_fd, fd);
	ATF_REQUIRE_EQ(1, nchanges);
	ATF_REQUIRE(changes != NULL && events == NULL && timeout == NULL);
	ATF_CHECK_EQ(0, nevents);
	ATF_CHECK_EQ(EVFILT_TIMER, changes[0].filter);
	ATF_CHECK_EQ(NOTE_SECONDS, changes[0].fflags);
	ATF_CHECK_EQ(1, changes[0].data);
	if (operation() == -1)
		return (-1);
	armed = true;
	return (0);
}
int
__wrap_service_provider_ready(struct service_provider *provider)
{
	ATF_REQUIRE(provider == &fake_provider);
	ATF_REQUIRE(armed);
	ATF_REQUIRE(fcntl(queue_fd, F_GETFD) != -1);
	ready_calls++;
	return (operation());
}
int
__wrap_service_provider_quiescing(struct service_provider *provider)
{
	ATF_REQUIRE(provider == &fake_provider);
	return (1); /* Stop immediately after successful startup. */
}
int
__wrap_service_provider_quiesce_complete(struct service_provider *provider,
    int status)
{
	ATF_REQUIRE(provider == &fake_provider);
	ATF_CHECK_EQ(0, status);
	/* Acknowledge only after event-loop resources have been released. */
	ATF_CHECK_ERRNO(EBADF, fcntl(queue_fd, F_GETFD) == -1);
	completed++;
	return (0);
}
ATF_TC_WITHOUT_HEAD(readiness_and_startup_cleanup);
ATF_TC_BODY(readiness_and_startup_cleanup, tc)
{
	for (unsigned failure = 0; failure <= 7; failure++) {
		fail_step = failure;
		step = ready_calls = destroyed = completed = 0;
		queue_fd = -1;
		armed = false;
		ATF_CHECK_EQ(failure == 0 ? 0 : 1, bsdmemory_test_main());
		ATF_CHECK_EQ(failure == 0 || failure == 7 ? 1 : 0, ready_calls);
		ATF_CHECK_EQ(failure == 1 ? 0 : 1, destroyed);
		ATF_CHECK_EQ(failure == 0 ? 1 : 0, completed);
		if (queue_fd >= 0)
			ATF_CHECK_ERRNO(EBADF, fcntl(queue_fd, F_GETFD) == -1);
	}
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, readiness_and_startup_cleanup);
	return (atf_no_error());
}
