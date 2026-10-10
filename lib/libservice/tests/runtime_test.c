/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <service_runtime.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

ATF_TC_WITHOUT_HEAD(retry_and_health);
ATF_TC_BODY(retry_and_health, tc)
{
	struct service_retry r;
	struct service_health h = { 0 };
	ATF_REQUIRE_EQ(0, service_retry_init(&r, 10, 25));
	ATF_REQUIRE(service_retry_ready(&r, 0));
	service_retry_result(&r, 100, false);
	ATF_CHECK(!service_retry_ready(&r, 109));
	ATF_CHECK(service_retry_ready(&r, 110));
	service_retry_result(&r, 110, false);
	ATF_CHECK_EQ(130, r.next_ms);
	service_retry_result(&r, 130, false);
	ATF_CHECK_EQ(155, r.next_ms);
	service_retry_result(&r, UINT64_MAX - 1, false);
	ATF_CHECK_EQ(UINT64_MAX, r.next_ms);
	service_retry_result(&r, 0, true);
	ATF_CHECK_EQ(0, r.next_ms);
	ATF_CHECK(service_health_record(&h, EIO));
	ATF_CHECK(!service_health_record(&h, EPIPE));
	ATF_CHECK_EQ(2, h.consecutive_failures);
	ATF_CHECK(service_health_record(&h, 0));
	ATF_CHECK_EQ(0, h.consecutive_failures);
	ATF_CHECK_EQ(2, h.changes);
	h.failures = UINT64_MAX;
	service_health_record(&h, EIO);
	ATF_CHECK_EQ(UINT64_MAX, h.failures);
}
ATF_TC_WITHOUT_HEAD(lease_ownership);
ATF_TC_BODY(lease_ownership, tc)
{
	struct service_lease_set *s;
	uint64_t a, b, c;
	ATF_REQUIRE_EQ(0, service_lease_set_create(2, &s));
	ATF_REQUIRE_EQ(0, service_lease_acquire(s, 1, &a));
	ATF_REQUIRE_EQ(0, service_lease_acquire(s, 2, &b));
	ATF_CHECK_ERRNO(ENOSPC, service_lease_acquire(s, 1, &c) == -1);
	ATF_CHECK_ERRNO(ENOENT, service_lease_release(s, 2, a) == -1);
	ATF_CHECK_EQ(2, service_lease_count(s));
	service_lease_release_owner(s, 1);
	ATF_CHECK_EQ(1, service_lease_count(s));
	ATF_REQUIRE_EQ(0, service_lease_acquire(s, 1, &c));
	ATF_CHECK(c != a && c != b);
	ATF_CHECK_ERRNO(ENOENT, service_lease_release(s, 1, a) == -1);
	ATF_REQUIRE_EQ(0, service_lease_release(s, 1, c));
	service_lease_release_owner(s, 2);
	ATF_CHECK_EQ(0, service_lease_count(s));
	service_lease_set_destroy(s);
}
static int
pending(void *p)
{
	(void)p;
	return (0);
}
static int
completed(void *p)
{
	(void)p;
	return (1);
}
static int
failed(void *p)
{
	(void)p;
	errno = EIO;
	return (-1);
}
ATF_TC_WITHOUT_HEAD(drain_deadline);
ATF_TC_BODY(drain_deadline, tc)
{
	uint64_t start = service_monotime_ms();
	ATF_CHECK_ERRNO(ETIMEDOUT, service_drain_wait(pending, NULL, 25) == -1);
	ATF_CHECK(service_monotime_ms() - start >= 25);
	ATF_CHECK(service_monotime_ms() - start < 1000);
	ATF_CHECK_EQ(0, service_drain_wait(completed, NULL, 0));
	ATF_CHECK_ERRNO(EIO, service_drain_wait(failed, NULL, 100) == -1);
}
static void *
thread_budget(void *p)
{
	uint32_t n = 10000;
	(void)p;
	if (service_budget_timeout(&n) == -1 || n != 10000)
		return ((void *)1);
	return (NULL);
}
ATF_TC_WITHOUT_HEAD(budget_scope);
ATF_TC_BODY(budget_scope, tc)
{
	pthread_t t;
	void *result;
	uint32_t n = 10000;
	int status;
	pid_t pid;
	ATF_REQUIRE_EQ(0, service_budget_begin(40));
	ATF_CHECK_ERRNO(EBUSY, service_budget_begin(10) == -1);
	ATF_REQUIRE_EQ(0, service_budget_timeout(&n));
	ATF_CHECK(n <= 40);
	ATF_REQUIRE_EQ(0, pthread_create(&t, NULL, thread_budget, NULL));
	ATF_REQUIRE_EQ(0, pthread_join(t, &result));
	ATF_CHECK(result == NULL);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		n = 10000;
		_exit(service_budget_timeout(&n) == 0 && n == 10000 ? 0 : 1);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	usleep(50000);
	n = UINT32_MAX;
	ATF_CHECK_ERRNO(ETIMEDOUT, service_budget_timeout(&n) == -1);
	service_budget_end();
	ATF_CHECK_EQ(0, service_budget_timeout(&n));
	ATF_CHECK_EQ(UINT32_MAX, n);
}
ATF_TC_WITHOUT_HEAD(listener_wait);
ATF_TC_BODY(listener_wait, tc)
{
	int fds[2], kq = kqueue();
	char c = 0;
	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, pipe(fds));
	ATF_CHECK_EQ(0, service_channels_wait(kq, NULL, 0, fds[0], 0));
	ATF_REQUIRE_EQ(1, write(fds[1], &c, 1));
	ATF_CHECK_EQ(1, service_channels_wait(kq, NULL, 0, fds[0], 100));
	close(fds[0]);
	close(fds[1]);
	close(kq);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, retry_and_health);
	ATF_TP_ADD_TC(tp, lease_ownership);
	ATF_TP_ADD_TC(tp, drain_deadline);
	ATF_TP_ADD_TC(tp, budget_scope);
	ATF_TP_ADD_TC(tp, listener_wait);
	return (atf_no_error());
}
