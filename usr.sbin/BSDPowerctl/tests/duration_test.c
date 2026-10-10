/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <powercmp.h>
#include <service_runtime.h>
#include <signal.h>
#include <time.h>
static uint64_t now_ms;
static int checks, releases, closed;
static bool interrupt_wait;
static uint64_t
fake_now(void)
{
	return (now_ms);
}
static int
fake_open(struct powercmp_client **p)
{
	*p = (void *)1;
	return (0);
}
static void
fake_close(struct powercmp_client *p)
{
	(void)p;
	closed++;
}
static int
fake_acquire(struct powercmp_client *p)
{
	(void)p;
	return (0);
}
static int
fake_release(struct powercmp_client *p)
{
	(void)p;
	releases++;
	return (0);
}
static int
fake_count(struct powercmp_client *p, uint32_t *count)
{
	uint32_t budget = 5000;
	(void)p;
	*count = 1;
	checks++;
	ATF_REQUIRE_EQ(0, service_budget_timeout(&budget));
	ATF_CHECK(budget <= 1000);
	now_ms += 900;
	return (0);
}
static int
fake_sleep(const struct timespec *delay, struct timespec *remain)
{
	(void)remain;
	if (interrupt_wait) {
		raise(SIGTERM);
		errno = EINTR;
		return (-1);
	}
	now_ms += delay->tv_sec * 1000 + delay->tv_nsec / 1000000;
	return (0);
}
#define main		      powerctl_main
#define service_monotime_ms   fake_now
#define nanosleep	      fake_sleep
#define powercmp_client_open  fake_open
#define powercmp_client_close fake_close
#define powercmp_inhibit      fake_acquire
#define powercmp_uninhibit    fake_release
#define powercmp_inhibitors   fake_count
int powerctl_main(int, char **);
#include "../BSDPowerctl.c"
#undef main
ATF_TC_WITHOUT_HEAD(slow_checks_count_toward_duration);
ATF_TC_BODY(slow_checks_count_toward_duration, tc)
{
	char prog[] = "BSDPowerctl", command[] = "inhibit", duration[] = "2";
	char *args[] = { prog, command, duration, NULL };
	ATF_CHECK_EQ(0, powerctl_main(3, args));
	ATF_CHECK_EQ(2000, now_ms);
	ATF_CHECK_EQ(1, checks);
	ATF_CHECK_EQ(1, releases);
	ATF_CHECK_EQ(1, closed);
}
ATF_TC_WITHOUT_HEAD(signal_skips_health_check);
ATF_TC_BODY(signal_skips_health_check, tc)
{
	char prog[] = "BSDPowerctl", command[] = "inhibit", duration[] = "2";
	char *args[] = { prog, command, duration, NULL };
	interrupt_wait = true;
	ATF_CHECK_EQ(0, powerctl_main(3, args));
	ATF_CHECK_EQ(0, checks);
	ATF_CHECK_EQ(1, releases);
	ATF_CHECK_EQ(1, closed);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, slow_checks_count_toward_duration);
	ATF_TP_ADD_TC(tp, signal_skips_health_check);
	return (atf_no_error());
}
