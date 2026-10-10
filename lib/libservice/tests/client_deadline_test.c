/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

static struct timespec fake_now, waited_until;
static unsigned wait_count;
static clockid_t condition_clock;

static int
capture_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
	ATF_REQUIRE(attr != NULL);
	ATF_REQUIRE_EQ(0, pthread_condattr_getclock(attr, &condition_clock));
	return (pthread_cond_init(cond, attr));
}

static int
capture_clock(clockid_t clock, struct timespec *now)
{
	ATF_REQUIRE_EQ(CLOCK_MONOTONIC, clock);
	*now = fake_now;
	return (0);
}

static int
capture_wait(pthread_cond_t *cond, pthread_mutex_t *mutex,
    const struct timespec *until)
{
	(void)cond;
	(void)mutex;
	waited_until = *until;
	wait_count++;
	return (ETIMEDOUT);
}

#define pthread_cond_init(...) capture_cond_init(__VA_ARGS__)
#define clock_gettime(...) capture_clock(__VA_ARGS__)
#define pthread_cond_timedwait(...) capture_wait(__VA_ARGS__)
#include "../service_client.c"
#undef pthread_cond_init
#undef clock_gettime
#undef pthread_cond_timedwait

ATF_TC_WITHOUT_HEAD(monotonic_condition);
ATF_TC_BODY(monotonic_condition, tc)
{
	pthread_cond_t cond;

	(void)tc;
	ATF_REQUIRE_EQ(0, monotonic_cond_init(&cond));
	ATF_CHECK_EQ(CLOCK_MONOTONIC, condition_clock);
	ATF_CHECK_EQ(0, pthread_cond_destroy(&cond));
}

ATF_TC_WITHOUT_HEAD(deadline_not_restarted);
ATF_TC_BODY(deadline_not_restarted, tc)
{
	struct timespec deadline = { .tv_sec = 100, .tv_nsec = 5000000 };

	(void)tc;
	/* Budget expired while this caller was acquiring the session mutex. */
	fake_now = (struct timespec){ .tv_sec = 100, .tv_nsec = 10000000 };
	wait_slice(NULL, NULL, &deadline, 10);
	ATF_CHECK_EQ(1, wait_count);
	ATF_CHECK_EQ(deadline.tv_sec, waited_until.tv_sec);
	ATF_CHECK_EQ(deadline.tv_nsec, waited_until.tv_nsec);
	/* Near a second boundary, a finite wait still uses the original end. */
	fake_now = (struct timespec){ .tv_sec = 99, .tv_nsec = 999000000 };
	wait_slice(NULL, NULL, &deadline, 10);
	ATF_CHECK_EQ(2, wait_count);
	ATF_CHECK_EQ(deadline.tv_sec, waited_until.tv_sec);
	ATF_CHECK_EQ(deadline.tv_nsec, waited_until.tv_nsec);
	/* Infinite calls use a bounded dispatch slice without reading a deadline. */
	wait_slice(NULL, NULL, NULL, SERVICE_CLIENT_TIMEOUT_INFINITE);
	ATF_CHECK_EQ(3, wait_count);
	ATF_CHECK_EQ(100, waited_until.tv_sec);
	ATF_CHECK_EQ(24000000, waited_until.tv_nsec);
	wait_slice(NULL, NULL, NULL, 0);
	ATF_CHECK_EQ(3, wait_count);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, monotonic_condition);
	ATF_TP_ADD_TC(tp, deadline_not_restarted);
	return (atf_no_error());
}
