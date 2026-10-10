/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <fcntl.h>
#include <string.h>
int bsdmemory_test_main(void);
#define main bsdmemory_test_main
#include "../BSDMemory.c"
#undef main

struct service_provider { int unused; };
static struct service_provider fake_provider;
static unsigned fail_step, step, ready_calls, destroyed, completed;
static int queue_fd = -1;
static bool armed, run_loop, fail_heartbeat;
static unsigned tick, heartbeats, source_opens, source_closes;
static unsigned notify_opens, notify_closes, sample_ticks, publications;
static unsigned published_ticks, published_levels[7];
static uint64_t current_state;
struct sysctlcmp_client { int unused; };
struct notify_client { int unused; };
static struct sysctlcmp_client source_client;
static struct notify_client notification_client;
uint64_t __wrap_service_monotime_ms(void);
int __wrap_service_provider_heartbeat(struct service_provider *);
int __wrap_sysctlcmp_client_open(struct sysctlcmp_client **);
void __wrap_sysctlcmp_client_close(struct sysctlcmp_client *);
int __wrap_sysctlcmp_get(struct sysctlcmp_client *, const char *, void *, size_t *);
int __wrap_notify_client_open_system(struct notify_client **);
void __wrap_notify_client_close(struct notify_client *);
int __wrap_notify_state_get(struct notify_client *, const char *, struct notify_state_reply *);
int __wrap_notify_state_set(struct notify_client *, const char *, uint64_t);
void __wrap_syslog(int, const char *, ...);

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
	if (run_loop && nchanges == 0) {
		ATF_REQUIRE(events != NULL && nevents == 1);
		memset(events, 0, sizeof(*events));
		events->filter = EVFILT_TIMER;
		tick++;
		return (1);
	}
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
	return (run_loop ? tick >= 7 : 1);
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

static void
require_budget(void)
{
	uint32_t timeout = UINT32_MAX;
	ATF_REQUIRE_EQ(0, service_budget_timeout(&timeout));
	ATF_REQUIRE(timeout <= 400);
}
uint64_t
__wrap_service_monotime_ms(void)
{
	return (tick * 1000);
}
void
__wrap_syslog(int priority, const char *format, ...)
{
	(void)priority; (void)format;
}
int
__wrap_service_provider_heartbeat(struct service_provider *provider)
{
	ATF_REQUIRE(provider == &fake_provider);
	require_budget();
	heartbeats++;
	return (fail_heartbeat && tick == 0 ? (errno = ETIMEDOUT, -1) : 0);
}
int
__wrap_sysctlcmp_client_open(struct sysctlcmp_client **out)
{
	require_budget();
	source_opens++;
	*out = &source_client;
	return (0);
}
void
__wrap_sysctlcmp_client_close(struct sysctlcmp_client *client)
{
	ATF_REQUIRE(client == &source_client);
	source_closes++;
}
int
__wrap_sysctlcmp_get(struct sysctlcmp_client *client, const char *name,
    void *value, size_t *length)
{
	ATF_REQUIRE(client == &source_client);
	require_budget();
	ATF_REQUIRE_EQ(sizeof(uint32_t), *length);
	if (strcmp(name, "vm.stats.vm.v_free_count") == 0) {
		sample_ticks |= 1U << tick;
		if (tick == 1 || tick == 2)
			return (errno = EIO, -1);
		*(uint32_t *)value = tick == 0 ? 1 : 10;
	} else if (strcmp(name, "vm.stats.vm.v_free_min") == 0)
		*(uint32_t *)value = 2;
	else {
		ATF_REQUIRE_STREQ("vm.stats.vm.v_free_target", name);
		*(uint32_t *)value = 4;
	}
	return (0);
}
int
__wrap_notify_client_open_system(struct notify_client **out)
{
	require_budget();
	notify_opens++;
	*out = &notification_client;
	return (0);
}
void
__wrap_notify_client_close(struct notify_client *client)
{
	ATF_REQUIRE(client == &notification_client);
	notify_closes++;
}
int
__wrap_notify_state_get(struct notify_client *client, const char *topic,
    struct notify_state_reply *out)
{
	ATF_REQUIRE(client == &notification_client);
	ATF_REQUIRE_STREQ(NOTIFY_PRESSURE_TOPIC, topic);
	require_budget();
	*out = (struct notify_state_reply){ .router_epoch = 1,
	    .generation = publications, .state = current_state };
	return (0);
}
int
__wrap_notify_state_set(struct notify_client *client, const char *topic,
    uint64_t state)
{
	ATF_REQUIRE(client == &notification_client);
	ATF_REQUIRE_STREQ(NOTIFY_PRESSURE_TOPIC, topic);
	require_budget();
	if (tick == 1)
		return (errno = ENOSPC, -1);
	ATF_REQUIRE(tick < 7);
	current_state = state;
	published_ticks |= 1U << tick;
	published_levels[tick] = state;
	publications++;
	return (0);
}
ATF_TC_WITHOUT_HEAD(loop_backoff_pressure_and_heartbeat);
ATF_TC_BODY(loop_backoff_pressure_and_heartbeat, tc)
{
	uint32_t timeout = UINT32_MAX;
	run_loop = true;
	ATF_REQUIRE_EQ(0, bsdmemory_test_main());
	ATF_CHECK_EQ(7, heartbeats);
	/* Failures at1/2 cause a skipped source retry at3, then recovery4/5/6. */
	ATF_CHECK_EQ(0x77, sample_ticks);
	ATF_CHECK_EQ(0x55, published_ticks);
	ATF_CHECK_EQ(4, publications);
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL, published_levels[0]);
	ATF_CHECK_EQ(NOTIFY_PRESSURE_UNKNOWN, published_levels[2]);
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL, published_levels[4]);
	ATF_CHECK_EQ(NOTIFY_PRESSURE_NORMAL, published_levels[6]);
	ATF_CHECK_EQ(3, source_opens);
	ATF_CHECK_EQ(source_opens, source_closes);
	ATF_CHECK_EQ(2, notify_opens);
	ATF_CHECK_EQ(notify_opens, notify_closes);
	ATF_CHECK_EQ(1, completed);
	ATF_CHECK_EQ(1, destroyed);
	ATF_REQUIRE_EQ(0, service_budget_timeout(&timeout));
	ATF_CHECK_EQ(UINT32_MAX, timeout);
}
ATF_TC_WITHOUT_HEAD(heartbeat_failure_cleans_up);
ATF_TC_BODY(heartbeat_failure_cleans_up, tc)
{
	uint32_t timeout = UINT32_MAX;
	run_loop = fail_heartbeat = true;
	ATF_REQUIRE_EQ(1, bsdmemory_test_main());
	ATF_CHECK_EQ(1, heartbeats);
	ATF_CHECK_EQ(1, source_opens);
	ATF_CHECK_EQ(1, notify_opens);
	ATF_CHECK_EQ(source_opens, source_closes);
	ATF_CHECK_EQ(notify_opens, notify_closes);
	ATF_CHECK_EQ(0, completed);
	ATF_CHECK_EQ(1, destroyed);
	ATF_CHECK_ERRNO(EBADF, fcntl(queue_fd, F_GETFD) == -1);
	ATF_REQUIRE_EQ(0, service_budget_timeout(&timeout));
	ATF_CHECK_EQ(UINT32_MAX, timeout);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, loop_backoff_pressure_and_heartbeat);
	ATF_TP_ADD_TC(tp, heartbeat_failure_cleans_up);
	ATF_TP_ADD_TC(tp, readiness_and_startup_cleanup);
	return (atf_no_error());
}
