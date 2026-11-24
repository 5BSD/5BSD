/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
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
	struct service_client client;

	(void)tc;
	memset(&client, 0, sizeof(client));
	/*
	 * A waiter sleeps to the call's own absolute deadline every time it
	 * waits: the deadline is passed through as is, never recomputed from
	 * the clock (no slice, no restarted budget).
	 */
	wait_wake(&client, &deadline, 10);
	wait_wake(&client, &deadline, 10);
	ATF_CHECK_EQ(2, wait_count);
	ATF_CHECK_EQ(deadline.tv_sec, waited_until.tv_sec);
	ATF_CHECK_EQ(deadline.tv_nsec, waited_until.tv_nsec);
	/* The kernel's sleeps get the same deadline, or none. */
	ATF_CHECK(kernel_deadline(&deadline, 10) == &deadline);
	ATF_CHECK(kernel_deadline(&deadline, 0) == &deadline);
	ATF_CHECK(kernel_deadline(&deadline,
	    SERVICE_CLIENT_TIMEOUT_INFINITE) == NULL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, monotonic_condition);
	ATF_TP_ADD_TC(tp, deadline_not_restarted);
	return (atf_no_error());
}
