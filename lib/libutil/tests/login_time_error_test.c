/* SPDX-License-Identifier: BSD-2-Clause */
/* Fault injection at the capability-list API; real account-policy evaluation. */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <login_cap.h>
#include <string.h>
#include <time.h>

static const char *failed_capability;
static unsigned int failures;
static const char *rule_capability;
static const char **rules;
static bool fail_localtime;

static bool disturb_conversion;

struct tm *__real_localtime(const time_t *);
struct tm *__real_localtime_r(const time_t *, struct tm *);
struct tm *__wrap_localtime(const time_t *);
struct tm *__wrap_localtime_r(const time_t *, struct tm *);

struct tm *
__wrap_localtime(const time_t *value)
{
	if (fail_localtime) {
		errno = EOVERFLOW;
		return (NULL);
	}
	return (__real_localtime(value));
}

struct tm *
__wrap_localtime_r(const time_t *value, struct tm *converted)
{
	if (fail_localtime) {
		errno = EOVERFLOW;
		return (NULL);
	}
	return (__real_localtime_r(value, converted));
}

const char **
login_getcaplist(login_cap_t *lc, const char *cap, const char *chars)
{
	(void)lc;
	(void)chars;
	if (disturb_conversion) {
		time_t other = 3600;

		ATF_REQUIRE(localtime(&other) != NULL);
	}
	if (failed_capability != NULL && strcmp(cap, failed_capability) == 0) {
		failures++;
		errno = ENOMEM;
	}
	if (rule_capability != NULL && strcmp(cap, rule_capability) == 0)
		return (rules);
	/* NULL without errno means the capability is absent. */
	return (NULL);
}

ATF_TC(capability_list_failure);
ATF_TC_HEAD(capability_list_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Time policy errors deny access; absent rules allow");
}
ATF_TC_BODY(capability_list_failure, tc)
{
	login_cap_t lc = {0};
	(void)tc;

	/* A stale caller errno must not turn an absent rule into an error. */
	errno = EIO;
	ATF_REQUIRE_EQ(1, auth_timeok(&lc, 1792584000));
	failed_capability = "times.allow";
	ATF_REQUIRE_EQ(0, auth_timeok(&lc, 1792584000));
	ATF_REQUIRE_EQ(1, failures);
	failed_capability = "times.deny";
	ATF_REQUIRE_EQ(0, auth_timeok(&lc, 1792584000));
	ATF_REQUIRE_EQ(2, failures);
	failed_capability = NULL;
	ATF_REQUIRE_EQ(1, auth_timeok(&lc, 1792584000));
}

ATF_TC(clock_conversion_failure);
ATF_TC_HEAD(clock_conversion_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Clock and conversion failures cannot bypass login time policy");
}
ATF_TC_BODY(clock_conversion_failure, tc)
{
	login_cap_t lc = {0};
	const char *all[] = { "Any", NULL };
	(void)tc;

	rule_capability = "times.deny";
	rules = all;
	ATF_REQUIRE_EQ(0, auth_timeok(&lc, (time_t)0));
	ATF_REQUIRE_EQ(0, auth_timeok(&lc, (time_t)-1));
	fail_localtime = true;
	ATF_REQUIRE_EQ(0, auth_timeok(&lc, 1792584000));
	/* Failure is not equivalent to an absent time restriction. */
	rule_capability = NULL;
	ATF_REQUIRE_EQ(0, auth_timeok(&lc, 1792584000));
	fail_localtime = false;
	ATF_REQUIRE_EQ(0, auth_timeok(&lc, (time_t)-1));
	ATF_REQUIRE_EQ(1, auth_timeok(&lc, (time_t)0));
	ATF_REQUIRE_EQ(1, auth_timeok(&lc, 1792584000));
}

ATF_TC(nested_time_conversion);
ATF_TC_HEAD(nested_time_conversion, tc)
{
	atf_tc_set_md_var(tc, "descr", "Nested conversion cannot replace the checked account timestamp");
}
ATF_TC_BODY(nested_time_conversion, tc)
{
	login_cap_t lc = {0};
	const char *midnight[] = { "Any0000-0001", NULL };
	(void)tc;

	ATF_REQUIRE_EQ(0, setenv("TZ", "UTC", 1));
	tzset();
	rules = midnight;
	disturb_conversion = true;
	rule_capability = "times.allow";
	ATF_CHECK_EQ(1, auth_timeok(&lc, (time_t)0));
	rule_capability = "times.deny";
	ATF_CHECK_EQ(0, auth_timeok(&lc, (time_t)0));
}

ATF_TC(time_expressions);
ATF_TC_HEAD(time_expressions, tc)
{
	atf_tc_set_md_var(tc, "descr", "Parse complete login time expressions without truncation");
}
ATF_TC_BODY(time_expressions, tc)
{
	const struct {
		const char *text;
		unsigned int days, start, end;
	} valid[] = {
		{"Any", LTM_ANY, 0, 1440},
		{"all0000-2400", LTM_ANY, 0, 1440},
		{"MoThFrSa1400-2200", LTM_MON|LTM_THU|LTM_FRI|LTM_SAT, 840, 1320},
		{"wK0900-1700", LTM_WK, 540, 1020},
		{"Wd0600-1800", LTM_WD, 360, 1080},
		{"0800-1700", LTM_ANY, 480, 1020},
		{"Mo0800", LTM_MON, 480, 1440},
		{"-1700", LTM_ANY, 0, 1020},
		{"Any0-30", LTM_ANY, 0, 30},
		{"None", LTM_NONE, 0, 0},
		{"Never", LTM_NONE, 0, 0},
	};
	const char *invalid[] = {NULL, "", "garbage", "Anygarbage",
	    "Any0800-1700junk", "Any-", "Any0800-", "Any2360-2400",
	    "Any2401", "Any999999999999999999999", "Any1700-0800",
	    "Any0800--1700", "Any 0800-1700", "Neverjunk"};
	login_time_t t;
	char long_rule[256];
	size_t i;
	(void)tc;

	for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
		errno = EIO;
		t = parse_lt(valid[i].text);
		ATF_REQUIRE_EQ_MSG(0, errno, "%s", valid[i].text);
		ATF_REQUIRE_EQ(valid[i].days, t.lt_dow);
		ATF_REQUIRE_EQ(valid[i].start, t.lt_start);
		ATF_REQUIRE_EQ(valid[i].end, t.lt_end);
	}
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		t = parse_lt(invalid[i]);
		ATF_REQUIRE_EQ(LTM_NONE, t.lt_dow);
		ATF_REQUIRE_EQ(EINVAL, errno);
	}
	/* Valid long inputs are parsed fully, not bounded by a copy buffer. */
	memset(long_rule, 0, sizeof(long_rule));
	for (i = 0; i < 40; i++)
		strcat(long_rule, "Mo");
	strcat(long_rule, "0800-1700");
	t = parse_lt(long_rule);
	ATF_REQUIRE_EQ(0, errno);
	ATF_REQUIRE_EQ(LTM_MON, t.lt_dow);
	ATF_REQUIRE_EQ(480, t.lt_start);
	strcat(long_rule, "junk");
	t = parse_lt(long_rule);
	ATF_REQUIRE_EQ(LTM_NONE, t.lt_dow);
	ATF_REQUIRE_EQ(EINVAL, errno);
}

ATF_TC(complete_time_lists);
ATF_TC_HEAD(complete_time_lists, tc)
{
	atf_tc_set_md_var(tc, "descr", "Reject malformed and oversized allow/deny lists, including entries after None");
}
ATF_TC_BODY(complete_time_lists, tc)
{
	login_cap_t lc = {0};
	const char *list[LC_MAXTIMES + 2] = {0};
	const char *caps[] = {"times.allow", "times.deny"};
	size_t i, c;
	(void)tc;

	rules = list;
	for (c = 0; c < 2; c++) {
		rule_capability = caps[c];
		list[0] = "Any";
		list[1] = "garbage";
		list[2] = NULL;
		ATF_REQUIRE_EQ(0, auth_timeok(&lc, 1792584000));
		list[0] = "None";
		ATF_REQUIRE_EQ(0, auth_timeok(&lc, 1792584000));
		list[1] = "Any";
		ATF_REQUIRE_EQ(c == 0, auth_timeok(&lc, 1792584000));
		for (i = 0; i < LC_MAXTIMES; i++)
			list[i] = "None";
		list[LC_MAXTIMES] = NULL;
		ATF_REQUIRE_EQ(c == 1, auth_timeok(&lc, 1792584000));
		list[LC_MAXTIMES] = "Any";
		ATF_REQUIRE_EQ(0, auth_timeok(&lc, 1792584000));
	}
}

ATF_TC(host_list_failure);
ATF_TC_HEAD(host_list_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Host policy lookup errors deny access");
}
ATF_TC_BODY(host_list_failure, tc)
{
	login_cap_t lc = {0};
	const char *caps[] = {"host.allow", "host.deny"};
	size_t i;
	(void)tc;

	errno = EIO;
	ATF_REQUIRE_EQ(1, auth_hostok(&lc, NULL, "192.0.2.1"));
	for (i = 0; i < 2; i++) {
		failed_capability = caps[i];
		ATF_REQUIRE_EQ(0, auth_hostok(&lc, NULL, "192.0.2.1"));
		ATF_REQUIRE_EQ(i + 1, failures);
	}
	failed_capability = NULL;
	ATF_REQUIRE_EQ(1, auth_hostok(&lc, NULL, "192.0.2.1"));
}

ATF_TC(tty_list_failure);
ATF_TC_HEAD(tty_list_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Terminal policy lookup errors deny access");
}
ATF_TC_BODY(tty_list_failure, tc)
{
	login_cap_t lc = {0};
	const char *caps[] = {"ttys.allow", "ttys.deny"};
	size_t i;
	(void)tc;

	errno = EIO;
	ATF_REQUIRE_EQ(1, auth_ttyok(&lc, "bip-test-terminal"));
	for (i = 0; i < 2; i++) {
		failed_capability = caps[i];
		ATF_REQUIRE_EQ(0, auth_ttyok(&lc, "bip-test-terminal"));
		ATF_REQUIRE_EQ(i + 1, failures);
	}
	failed_capability = NULL;
	ATF_REQUIRE_EQ(1, auth_ttyok(&lc, "bip-test-terminal"));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, capability_list_failure);
	ATF_TP_ADD_TC(tp, time_expressions);
	ATF_TP_ADD_TC(tp, clock_conversion_failure);
	ATF_TP_ADD_TC(tp, nested_time_conversion);
	ATF_TP_ADD_TC(tp, complete_time_lists);
	ATF_TP_ADD_TC(tp, host_list_failure);
	ATF_TP_ADD_TC(tp, tty_list_failure);
	return (atf_no_error());
}
