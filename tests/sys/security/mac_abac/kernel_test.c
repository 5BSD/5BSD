/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mac.h>
#include <sys/sysctl.h>

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

ATF_TC(object_context_operations);
ATF_TC_HEAD(object_context_operations, tc)
{
	atf_tc_set_md_var(tc, "descr", "unsupported object contexts reject add/load and preserve old policy");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(object_context_operations, tc)
{
	struct abac_rule_load_arg load;
	struct abac_rule_arg *rule;
	const uint32_t operations[] = { ABAC_OP_READ,
	    ABAC_OP_SIGNAL | ABAC_OP_READ, ABAC_OP_ALL };
	size_t size, length;
	uint32_t sentinel;
	int value;

	if (strcmp(atf_tc_get_config_var_wd(tc, "disposable_vm", "no"), "yes") != 0)
		atf_tc_skip("requires disposable_vm=yes; modifies isolated guest policy");
	length = sizeof(value);
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.mode", &value,
	    &length, NULL, 0) == 0);
	if (value != ABAC_MODE_PERMISSIVE)
		atf_tc_skip("requires permissive ABAC");
	length = sizeof(value);
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.rule_count", &value,
	    &length, NULL, 0) == 0);
	if (value != 0)
		atf_tc_skip("requires empty disposable guest rule table");

	sentinel = add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC, 0);
	size = sizeof(*rule) + 4;
	rule = calloc(1, size);
	ATF_REQUIRE(rule != NULL);
	rule->vr_action = ABAC_ACTION_DENY;
	rule->vr_subject_len = 2;
	rule->vr_object_len = 2;
	rule->vr_obj_context.vc_flags = ABAC_CTX_UID;
	rule->vr_obj_context.vc_uid = 0;
	memcpy(rule + 1, "*\0*\0", 4);
	memset(&load, 0, sizeof(load));
	load.vrl_count = 1;
	load.vrl_buflen = size;
	load.vrl_buf = rule;
	for (size_t i = 0; i < nitems(operations); i++) {
		rule->vr_operations = operations[i];
		errno = 0;
		ATF_REQUIRE_EQ(-1, mac_syscall("mac_abac", ABAC_SYS_RULE_ADD, rule));
		ATF_REQUIRE_EQ(EINVAL, errno);
		check_access(ABAC_OP_EXEC, EACCES, true);
		errno = 0;
		ATF_REQUIRE_EQ(-1, mac_syscall("mac_abac", ABAC_SYS_RULE_LOAD, &load));
		ATF_REQUIRE_EQ(EINVAL, errno);
		check_access(ABAC_OP_EXEC, EACCES, true);
	}
	/* A process-only combination remains representable. */
	rule->vr_operations = ABAC_OP_DEBUG | ABAC_OP_SIGNAL | ABAC_OP_SCHED | ABAC_OP_WAIT;
	call_ok(ABAC_SYS_RULE_ADD, rule);
	call_ok(ABAC_SYS_RULE_REMOVE, &rule->vr_id);
	call_ok(ABAC_SYS_RULE_REMOVE, &sentinel);
	free(rule);
}

static uint32_t
matched_rule(uint32_t operation, uint32_t expected)
{
	static const char subject[] = "type=subject";
	static const char object[] = "type=object";
	struct abac_test_arg *test;
	char *data;
	uint32_t id;

	test = calloc(1, sizeof(*test) + sizeof(subject) + sizeof(object));
	ATF_REQUIRE(test != NULL);
	test->vt_operation = operation;
	test->vt_subject_len = sizeof(subject);
	test->vt_object_len = sizeof(object);
	data = (char *)(test + 1);
	memcpy(data, subject, sizeof(subject));
	memcpy(data + sizeof(subject), object, sizeof(object));
	call_ok(ABAC_SYS_TEST, test);
	ATF_REQUIRE_EQ(expected, test->vt_result);
	id = test->vt_rule_id;
	free(test);
	return (id);
}

static int
rule_count(void)
{
	size_t length;
	int value;

	length = sizeof(value);
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.rule_count", &value,
	    &length, NULL, 0) == 0);
	return (value);
}

/*
 * A removed rule's slot is reusable: a long-lived add/remove workload keeps
 * adding rules after ABAC_MAX_RULES additions in total.  The table used to
 * append at a high-water mark that only a full clear reset, so the add after
 * the ABAC_MAX_RULES-th failed with ENOSPC while one rule was loaded.
 */
ATF_TC(remove_frees_slot);
ATF_TC_HEAD(remove_frees_slot, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "removing a rule frees its slot for later additions");
}
ATF_TC_BODY(remove_frees_slot, tc)
{
	uint32_t first, id;
	int i;
	(void)tc;

	reset_policy(0);
	first = add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC, 0);
	for (i = 0; i < ABAC_MAX_RULES + 16; i++) {
		id = add_rule(ABAC_ACTION_ALLOW, ABAC_OP_EXEC, 0);
		call_ok(ABAC_SYS_RULE_REMOVE, &id);
	}
	ATF_REQUIRE_EQ(1, rule_count());
	ATF_REQUIRE_EQ(first, matched_rule(ABAC_OP_EXEC, EACCES));
	reset_policy(0);
}

/* The same for rules removed by clearing their set. */
ATF_TC(set_clear_frees_slots);
ATF_TC_HEAD(set_clear_frees_slots, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "clearing a set frees its rules' slots for later additions");
}
ATF_TC_BODY(set_clear_frees_slots, tc)
{
	uint16_t set;
	uint32_t first;
	int i, j;
	(void)tc;

	reset_policy(0);
	first = add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC, 0);
	set = 7;
	for (i = 0; i < ABAC_MAX_RULES / 256 + 1; i++) {
		for (j = 0; j < 256; j++)
			(void)add_rule(ABAC_ACTION_ALLOW, ABAC_OP_EXEC, set);
		call_ok(ABAC_SYS_SET_CLEAR, &set);
	}
	ATF_REQUIRE_EQ(1, rule_count());
	ATF_REQUIRE_EQ(first, matched_rule(ABAC_OP_EXEC, EACCES));
	reset_policy(0);
}

/*
 * Reusing slots keeps first-match order: a rule added after a removal is
 * evaluated after every rule added before it, whichever slot the removal
 * freed.
 */
ATF_TC(remove_keeps_order);
ATF_TC_HEAD(remove_keeps_order, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "rules added after a removal match after older rules");
}
ATF_TC_BODY(remove_keeps_order, tc)
{
	uint32_t a, b, c, d;
	(void)tc;

	reset_policy(0);
	a = add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC, 0);
	b = add_rule(ABAC_ACTION_ALLOW, ABAC_OP_EXEC, 0);
	c = add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC, 0);
	ATF_REQUIRE_EQ(a, matched_rule(ABAC_OP_EXEC, EACCES));
	call_ok(ABAC_SYS_RULE_REMOVE, &a);
	ATF_REQUIRE_EQ(b, matched_rule(ABAC_OP_EXEC, 0));
	d = add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC, 0);
	ATF_REQUIRE_EQ(b, matched_rule(ABAC_OP_EXEC, 0));
	call_ok(ABAC_SYS_RULE_REMOVE, &b);
	ATF_REQUIRE_EQ(c, matched_rule(ABAC_OP_EXEC, EACCES));
	call_ok(ABAC_SYS_RULE_REMOVE, &c);
	ATF_REQUIRE_EQ(d, matched_rule(ABAC_OP_EXEC, EACCES));
	ATF_REQUIRE_EQ(1, rule_count());
	reset_policy(0);
}

#define ADD_KERNEL_OPERATION_CASES(name, value)                              \
	ATF_TP_ADD_TC(tp, kernel_allow_##name);                               \
	ATF_TP_ADD_TC(tp, kernel_deny_##name);                                \
	ATF_TP_ADD_TC(tp, kernel_disabled_set_##name);

ATF_TP_ADD_TCS(tp)
{
	ABAC_OPERATION_LIST(ADD_KERNEL_OPERATION_CASES)
	ATF_TP_ADD_TC(tp, object_context_operations);
	ATF_TP_ADD_TC(tp, atomic_load_rollback);
	ATF_TP_ADD_TC(tp, atomic_clear_exact);
	ATF_TP_ADD_TC(tp, load_reserved);
	ATF_TP_ADD_TC(tp, set_full_range);
	ATF_TP_ADD_TC(tp, default_policy_validation);
	ATF_TP_ADD_TC(tp, remove_frees_slot);
	ATF_TP_ADD_TC(tp, set_clear_frees_slots);
	ATF_TP_ADD_TC(tp, remove_keeps_order);
	return (atf_no_error());
}
