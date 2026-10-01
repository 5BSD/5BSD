/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Coverage for ABAC_OP_MPROTECT reaching mprotect(2).
 *
 * kernel_test's generated cases drive ABAC_SYS_TEST, which exercises the rule
 * engine without performing the operation, so they pass whether or not the
 * policy is ever consulted for a real mprotect(2).  That is how mac_abac came
 * to register mpo_vnode_check_mprotect -- an entry point the kernel never
 * calls -- and see no mprotect at all.  These cases close that gap: they arm a
 * deny rule, call mprotect(2), and assert the rule engine was consulted.
 *
 * Two deliberate choices keep this safe to run on a live system:
 *
 * The mode is left PERMISSIVE.  The hooks still evaluate rules and count the
 * denial (abac_rules_check bumps security.mac.mac_abac.denied) and then return
 * 0, so the counter proves consultation without a global enforcement flip.
 * Switching to enforcing would deny mprotect(2) system-wide for the window
 * between arming and cleanup; rtld needs mprotect(2), so a failure in that
 * window leaves a machine where nothing can exec.  That is not a theoretical
 * concern: it happened while developing this test.
 *
 * Every rule carries a subject label unique to this process, so the armed rule
 * cannot match anything else even while it is loaded.  Since the rule table is
 * cleared first, the only rule present is ours, and any denial counted across
 * the mprotect(2) call is necessarily ours.
 */

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/mac_abac/mac_abac.h>

#define	TEST_SET	65534
#define	SUBJECT_TYPE	"type=abac-mprotect-test"

static void
call_ok(int command, void *argument)
{
	ATF_REQUIRE_MSG(mac_syscall("mac_abac", command, argument) == 0,
	    "command %d failed: %s", command, strerror(errno));
}

static uint64_t
denied_count(void)
{
	uint64_t value;
	size_t len = sizeof(value);

	ATF_REQUIRE_MSG(sysctlbyname("security.mac.mac_abac.denied", &value,
	    &len, NULL, 0) == 0, "read denied counter: %s", strerror(errno));
	return (value);
}

static void
require_permissive(void)
{
	int mode;
	size_t len = sizeof(mode);

	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.mode", &mode, &len,
	    NULL, 0) == 0);
	if (mode != ABAC_MODE_PERMISSIVE)
		atf_tc_skip("mode is %d; these cases require permissive (%d) "
		    "so an armed deny cannot affect the system", mode,
		    ABAC_MODE_PERMISSIVE);
}

/* Label this process so the armed rule cannot match any other subject. */
static void
label_self(void)
{
	mac_t label;

	ATF_REQUIRE_MSG(mac_from_text(&label, "mac_abac/" SUBJECT_TYPE) == 0,
	    "mac_from_text: %s", strerror(errno));
	ATF_REQUIRE_MSG(mac_set_proc(label) == 0, "mac_set_proc: %s",
	    strerror(errno));
	mac_free(label);
}

static void
arm_deny(void)
{
	static const char subject[] = SUBJECT_TYPE;
	static const char object[] = "*";
	struct abac_rule_arg *rule;
	struct abac_set_range range;
	char *data;
	size_t size;
	int defpol = 0;			/* allow: only our rule can deny */

	call_ok(ABAC_SYS_RULE_CLEAR, NULL);
	call_ok(ABAC_SYS_SETDEFPOL, &defpol);

	size = sizeof(*rule) + sizeof(subject) + sizeof(object);
	rule = calloc(1, size);
	ATF_REQUIRE(rule != NULL);
	rule->vr_action = ABAC_ACTION_DENY;
	rule->vr_set = TEST_SET;
	rule->vr_operations = ABAC_OP_MPROTECT;
	rule->vr_subject_len = sizeof(subject);
	rule->vr_object_len = sizeof(object);
	data = (char *)(rule + 1);
	memcpy(data, subject, sizeof(subject));
	memcpy(data + sizeof(subject), object, sizeof(object));
	call_ok(ABAC_SYS_RULE_ADD, rule);
	free(rule);

	range.vsr_start = TEST_SET;
	range.vsr_end = TEST_SET;
	call_ok(ABAC_SYS_SET_ENABLE, &range);
}

static void
disarm(void)
{
	struct abac_set_range range;

	range.vsr_start = TEST_SET;
	range.vsr_end = TEST_SET;
	(void)mac_syscall("mac_abac", ABAC_SYS_SET_DISABLE, &range);
	(void)mac_syscall("mac_abac", ABAC_SYS_RULE_CLEAR, NULL);
}

ATF_TC_WITH_CLEANUP(mprotect_consults_policy);
ATF_TC_HEAD(mprotect_consults_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mprotect(2) on an anonymous mapping consults ABAC_OP_MPROTECT");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(mprotect_consults_policy, tc)
{
	uint64_t before, after;
	void *p;

	(void)tc;
	require_permissive();
	p = mmap(NULL, getpagesize(), PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	label_self();
	arm_deny();

	before = denied_count();
	/* Permissive: the deny is counted, the call still succeeds. */
	ATF_REQUIRE_EQ_MSG(0, mprotect(p, getpagesize(),
	    PROT_READ | PROT_WRITE), "mprotect: %s", strerror(errno));
	after = denied_count();

	ATF_REQUIRE_MSG(after > before,
	    "no denial counted across mprotect(2) (%ju -> %ju): the policy "
	    "was never consulted, so the MAC hook is not wired to the syscall",
	    (uintmax_t)before, (uintmax_t)after);
}
ATF_TC_CLEANUP(mprotect_consults_policy, tc)
{
	(void)tc;
	disarm();
}

/*
 * The anonymous case above exercises the path where no backing vnode exists
 * and the hook evaluates against the default object.  A file-backed mapping
 * takes the other path: the vnode is resolved from the address and its label
 * selected.  Both must reach the rule engine.
 */
ATF_TC_WITH_CLEANUP(mprotect_consults_policy_file_backed);
ATF_TC_HEAD(mprotect_consults_policy_file_backed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mprotect(2) on a file-backed mapping consults ABAC_OP_MPROTECT");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(mprotect_consults_policy_file_backed, tc)
{
	uint64_t before, after;
	void *p;
	int fd;

	(void)tc;
	require_permissive();
	fd = open("mapped", O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE_MSG(fd >= 0, "open: %s", strerror(errno));
	ATF_REQUIRE(ftruncate(fd, getpagesize()) == 0);
	p = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	label_self();
	arm_deny();

	before = denied_count();
	ATF_REQUIRE_EQ_MSG(0, mprotect(p, getpagesize(),
	    PROT_READ | PROT_WRITE), "mprotect: %s", strerror(errno));
	after = denied_count();
	(void)close(fd);

	ATF_REQUIRE_MSG(after > before,
	    "no denial counted for a file-backed mapping (%ju -> %ju)",
	    (uintmax_t)before, (uintmax_t)after);
}
ATF_TC_CLEANUP(mprotect_consults_policy_file_backed, tc)
{
	(void)tc;
	disarm();
}

/*
 * A rule that does not name ABAC_OP_MPROTECT must not be consulted for one,
 * which keeps the two cases above honest: they would also pass if every hook
 * counted a denial for every rule.
 */
ATF_TC_WITH_CLEANUP(unrelated_operation_is_not_consulted);
ATF_TC_HEAD(unrelated_operation_is_not_consulted, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a deny rule for another operation is not counted by mprotect(2)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(unrelated_operation_is_not_consulted, tc)
{
	static const char subject[] = SUBJECT_TYPE;
	static const char object[] = "*";
	struct abac_rule_arg *rule;
	struct abac_set_range range;
	uint64_t before, after;
	char *data;
	size_t size;
	void *p;
	int defpol = 0;

	(void)tc;
	require_permissive();
	p = mmap(NULL, getpagesize(), PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	label_self();

	call_ok(ABAC_SYS_RULE_CLEAR, NULL);
	call_ok(ABAC_SYS_SETDEFPOL, &defpol);
	size = sizeof(*rule) + sizeof(subject) + sizeof(object);
	rule = calloc(1, size);
	ATF_REQUIRE(rule != NULL);
	rule->vr_action = ABAC_ACTION_DENY;
	rule->vr_set = TEST_SET;
	rule->vr_operations = ABAC_OP_LISTEN;	/* never reached by mprotect */
	rule->vr_subject_len = sizeof(subject);
	rule->vr_object_len = sizeof(object);
	data = (char *)(rule + 1);
	memcpy(data, subject, sizeof(subject));
	memcpy(data + sizeof(subject), object, sizeof(object));
	call_ok(ABAC_SYS_RULE_ADD, rule);
	free(rule);
	range.vsr_start = TEST_SET;
	range.vsr_end = TEST_SET;
	call_ok(ABAC_SYS_SET_ENABLE, &range);

	before = denied_count();
	ATF_REQUIRE_EQ(0, mprotect(p, getpagesize(), PROT_READ | PROT_WRITE));
	after = denied_count();

	ATF_REQUIRE_EQ_MSG(before, after,
	    "mprotect(2) counted a denial against a listen-only rule "
	    "(%ju -> %ju)", (uintmax_t)before, (uintmax_t)after);
}
ATF_TC_CLEANUP(unrelated_operation_is_not_consulted, tc)
{
	(void)tc;
	disarm();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mprotect_consults_policy);
	ATF_TP_ADD_TC(tp, mprotect_consults_policy_file_backed);
	ATF_TP_ADD_TC(tp, unrelated_operation_is_not_consulted);
	return (atf_no_error());
}
