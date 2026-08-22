/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/mac.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <security/mac_abac/mac_abac.h>

static void
call_ok(int command, void *argument)
{
	ATF_REQUIRE_MSG(mac_syscall("mac_abac", command, argument) == 0,
	    "command %d failed: %s", command, strerror(errno));
}

static void
reset_policy(int default_policy)
{
	struct abac_set_range range;

	call_ok(ABAC_SYS_RULE_CLEAR, NULL);
	call_ok(ABAC_SYS_SETDEFPOL, &default_policy);
	range.vsr_start = 65535;
	range.vsr_end = 65535;
	call_ok(ABAC_SYS_SET_ENABLE, &range);
}

static uint32_t
add_rule(uint8_t action, uint32_t operation, uint16_t set)
{
	struct abac_rule_arg *rule;
	char *data;
	size_t size;
	uint32_t id;

	size = sizeof(*rule) + 4;
	rule = calloc(1, size);
	ATF_REQUIRE(rule != NULL);
	rule->vr_action = action;
	rule->vr_set = set;
	rule->vr_operations = operation;
	rule->vr_subject_len = 2;
	rule->vr_object_len = 2;
	data = (char *)(rule + 1);
	memcpy(data, "*\0*\0", 4);
	call_ok(ABAC_SYS_RULE_ADD, rule);
	id = rule->vr_id;
	free(rule);
	return (id);
}

static void
check_access(uint32_t operation, uint32_t expected, bool expect_rule)
{
	static const char subject[] = "type=subject";
	static const char object[] = "type=object";
	struct abac_test_arg *test;
	char *data;
	size_t size;

	size = sizeof(*test) + sizeof(subject) + sizeof(object);
	test = calloc(1, size);
	ATF_REQUIRE(test != NULL);
	test->vt_operation = operation;
	test->vt_subject_len = sizeof(subject);
	test->vt_object_len = sizeof(object);
	data = (char *)(test + 1);
	memcpy(data, subject, sizeof(subject));
	memcpy(data + sizeof(subject), object, sizeof(object));
	call_ok(ABAC_SYS_TEST, test);
	ATF_REQUIRE_EQ(expected, test->vt_result);
	if (expect_rule)
		ATF_REQUIRE(test->vt_rule_id != 0);
	else
		ATF_REQUIRE_EQ(0, test->vt_rule_id);
	free(test);
}

#define DEFINE_KERNEL_OPERATION_CASES(name, value)                          \
ATF_TC(kernel_allow_##name);                                                 \
ATF_TC_HEAD(kernel_allow_##name, tc)                                         \
{                                                                            \
	atf_tc_set_md_var(tc, "descr", "kernel allow decision for " #name);  \
}                                                                            \
ATF_TC_BODY(kernel_allow_##name, tc)                                         \
{                                                                            \
	(void)tc;                                                              \
	reset_policy(1);                                                       \
	(void)add_rule(ABAC_ACTION_ALLOW, (value), 0);                         \
	check_access((value), 0, true);                                        \
}                                                                            \
ATF_TC(kernel_deny_##name);                                                  \
ATF_TC_HEAD(kernel_deny_##name, tc)                                          \
{                                                                            \
	atf_tc_set_md_var(tc, "descr", "kernel deny decision for " #name);   \
}                                                                            \
ATF_TC_BODY(kernel_deny_##name, tc)                                          \
{                                                                            \
	(void)tc;                                                              \
	reset_policy(0);                                                       \
	(void)add_rule(ABAC_ACTION_DENY, (value), 0);                          \
	check_access((value), EACCES, true);                                   \
}                                                                            \
ATF_TC(kernel_disabled_set_##name);                                          \
ATF_TC_HEAD(kernel_disabled_set_##name, tc)                                  \
{                                                                            \
	atf_tc_set_md_var(tc, "descr", "disabled set is skipped for " #name);\
}                                                                            \
ATF_TC_BODY(kernel_disabled_set_##name, tc)                                  \
{                                                                            \
	struct abac_set_range range;                                           \
	(void)tc;                                                              \
	reset_policy(0);                                                       \
	(void)add_rule(ABAC_ACTION_DENY, (value), 65535);                      \
	range.vsr_start = 65535;                                               \
	range.vsr_end = 65535;                                                 \
	call_ok(ABAC_SYS_SET_DISABLE, &range);                                 \
	check_access((value), 0, false);                                       \
}

ABAC_OPERATION_LIST(DEFINE_KERNEL_OPERATION_CASES)

ATF_TC(atomic_load_rollback);
ATF_TC_HEAD(atomic_load_rollback, tc)
{
	atf_tc_set_md_var(tc, "descr", "malformed atomic load preserves policy");
}
ATF_TC_BODY(atomic_load_rollback, tc)
{
	struct abac_rule_load_arg load;
	struct abac_rule_arg *bad;
	char *data;
	size_t size;
	(void)tc;

	reset_policy(0);
	(void)add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC, 0);
	size = sizeof(*bad) + 4;
	bad = calloc(1, size);
	ATF_REQUIRE(bad != NULL);
	bad->vr_action = ABAC_ACTION_ALLOW;
	bad->vr_operations = ABAC_OP_EXEC;
	bad->vr_subject_len = 2;
	bad->vr_object_len = 2;
	data = (char *)(bad + 1);
	memcpy(data, "xx*\0", 4); /* subject has no terminating NUL */
	memset(&load, 0, sizeof(load));
	load.vrl_count = 1;
	load.vrl_buflen = size;
	load.vrl_buf = bad;
	errno = 0;
	ATF_REQUIRE_EQ(-1, mac_syscall("mac_abac", ABAC_SYS_RULE_LOAD, &load));
	ATF_REQUIRE_EQ(EINVAL, errno);
	free(bad);
	check_access(ABAC_OP_EXEC, EACCES, true);
}

ATF_TC(atomic_clear_exact);
ATF_TC_HEAD(atomic_clear_exact, tc)
{
	atf_tc_set_md_var(tc, "descr", "zero-rule atomic load requires empty buffer");
}
ATF_TC_BODY(atomic_clear_exact, tc)
{
	struct abac_rule_load_arg load;
	char byte = 0;
	(void)tc;

	reset_policy(0);
	(void)add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC, 0);
	memset(&load, 0, sizeof(load));
	load.vrl_buf = &byte;
	errno = 0;
	ATF_REQUIRE_EQ(-1, mac_syscall("mac_abac", ABAC_SYS_RULE_LOAD, &load));
	ATF_REQUIRE_EQ(EINVAL, errno);
	check_access(ABAC_OP_EXEC, EACCES, true);
	load.vrl_buf = NULL;
	call_ok(ABAC_SYS_RULE_LOAD, &load);
	check_access(ABAC_OP_EXEC, 0, false);
}

ATF_TC(load_reserved);
ATF_TC_HEAD(load_reserved, tc)
{
	atf_tc_set_md_var(tc, "descr", "reserved atomic-load fields are rejected");
}
ATF_TC_BODY(load_reserved, tc)
{
	struct abac_rule_load_arg load;
	(void)tc;
	memset(&load, 0, sizeof(load));
	load.vrl_reserved = 1;
	errno = 0;
	ATF_REQUIRE_EQ(-1, mac_syscall("mac_abac", ABAC_SYS_RULE_LOAD, &load));
	ATF_REQUIRE_EQ(EINVAL, errno);
}

ATF_TC(set_full_range);
ATF_TC_HEAD(set_full_range, tc)
{
	atf_tc_set_md_var(tc, "descr", "set range ending at 65535 terminates");
}
ATF_TC_BODY(set_full_range, tc)
{
	struct abac_set_range range;
	(void)tc;
	range.vsr_start = 0;
	range.vsr_end = 65535;
	call_ok(ABAC_SYS_SET_DISABLE, &range);
	call_ok(ABAC_SYS_SET_ENABLE, &range);
}

ATF_TC(default_policy_validation);
ATF_TC_HEAD(default_policy_validation, tc)
{
	atf_tc_set_md_var(tc, "descr", "default policy accepts only allow or deny");
}
ATF_TC_BODY(default_policy_validation, tc)
{
	int value = 2;
	(void)tc;
	errno = 0;
	ATF_REQUIRE_EQ(-1, mac_syscall("mac_abac", ABAC_SYS_SETDEFPOL, &value));
	ATF_REQUIRE_EQ(EINVAL, errno);
}

#define ADD_KERNEL_OPERATION_CASES(name, value)                              \
	ATF_TP_ADD_TC(tp, kernel_allow_##name);                               \
	ATF_TP_ADD_TC(tp, kernel_deny_##name);                                \
	ATF_TP_ADD_TC(tp, kernel_disabled_set_##name);

ATF_TP_ADD_TCS(tp)
{
	ABAC_OPERATION_LIST(ADD_KERNEL_OPERATION_CASES)
	ATF_TP_ADD_TC(tp, atomic_load_rollback);
	ATF_TP_ADD_TC(tp, atomic_clear_exact);
	ATF_TP_ADD_TC(tp, load_reserved);
	ATF_TP_ADD_TC(tp, set_full_range);
	ATF_TP_ADD_TC(tp, default_policy_validation);
	return (atf_no_error());
}
