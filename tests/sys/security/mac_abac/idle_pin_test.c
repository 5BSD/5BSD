/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Pins of mac_abac behaviour that idle gating must keep (P-A*), and of the
 * per-check work it removes (D-A1).
 *
 * The P-A cases hold on a kernel whose hooks evaluate every check and must
 * hold unchanged once hooks no rule names stop evaluating: a rule is
 * enforced from the moment the call that added it returns and stops being
 * enforced when it goes; disabled sets do not apply; an atomic load replaces
 * what applies; default-deny is observed even with no rule; and the
 * rule-independent label protections deny with an empty table.
 *
 * D-A1 counts evaluations of an operation no rule names.  Before the gates
 * every stat(2) was evaluated; ABAC_IDLE_GATED selects the answer the kernel
 * under test must give.
 */

#include "idle_common.h"

#ifndef ABAC_IDLE_GATED
#define	ABAC_IDLE_GATED	0	/* kernel predates the idle gates */
#endif

static void
idle_head(atf_tc_t *tc, const char *descr)
{

	atf_tc_set_md_var(tc, "descr", descr);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}

#define	IDLE_TC(name, descr)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc) { idle_head(tc, descr); }				\
ATF_TC_CLEANUP(name, tc) { (void)tc; idle_cleanup(); }			\
ATF_TC_BODY(name, tc)

IDLE_TC(p_a1_enforcing_no_rule,
    "P-A1: enforcing, no rule: a labelled subject reads, writes, stats, execs")
{
	struct lworker w;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	lworker_start(&w);
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_READ), "read");
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_WRITE), "write");
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_STAT), "stat");
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_EXEC), "exec");
	lworker_stop(&w);
}

IDLE_TC(p_a2_a3_rule_add_remove,
    "P-A2/P-A3: a deny-read rule applies when its add returns, not after "
    "its remove returns")
{
	struct lworker w;
	uint32_t id;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	lworker_start(&w);
	ATF_REQUIRE_EQ(0, lworker_do(&w, LW_READ));
	id = idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_READ);
	ATF_CHECK_EQ_MSG(EACCES, lworker_do(&w, LW_READ),
	    "first read after the add");
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_WRITE), "write is not read");
	idle_remove_rule(id);
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_READ),
	    "first read after the remove");
	lworker_stop(&w);
}

IDLE_TC(p_a4_default_deny_no_rule,
    "P-A4: default deny with no rule is evaluated (permissive counts it)")
{
	struct lworker w;
	uint64_t before, after;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_mode(ABAC_MODE_PERMISSIVE);
	lworker_start(&w);
	before = idle_sysctl_u64("security.mac.mac_abac.denied");
	idle_set_defpol(1);
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_READ), "permissive read");
	idle_set_defpol(0);
	after = idle_sysctl_u64("security.mac.mac_abac.denied");
	ATF_CHECK_MSG(after > before, "no denial counted (%ju -> %ju)",
	    (uintmax_t)before, (uintmax_t)after);
	lworker_stop(&w);
}

IDLE_TC(p_a5_label_attribute_protected,
    "P-A5: no rule: a labelled subject cannot delete a mac_abac attribute")
{
	pid_t pid;
	int status;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		mac_t label;

		if (mac_from_text(&label, "mac_abac/" SUBJ_LABEL) != 0 ||
		    mac_set_proc(label) != 0)
			_exit(100);
		if (extattr_delete_file(idle_obj, EXTATTR_NAMESPACE_SYSTEM,
		    "mac_abac") == 0)
			_exit(0);
		_exit(errno);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
	ATF_CHECK_EQ_MSG(EPERM, WEXITSTATUS(status),
	    "extattr_delete_file returned %d", WEXITSTATUS(status));
}

/*
 * mac_abac denies every pipe relabel (abac_pipe_check_relabel), but no
 * compiled-in policy internalizes a pipe label, so mac_set_fd(2) is refused
 * before any relabel check runs.  Pinned as observed.
 */
IDLE_TC(p_a6_pipe_relabel,
    "P-A6: no rule: relabelling a pipe through mac_set_fd fails")
{
	mac_t label;
	int p[2];

	(void)tc;
	idle_save_state();
	ATF_REQUIRE(pipe(p) == 0);
	ATF_REQUIRE(mac_from_text(&label, "mac_abac/" OBJ_LABEL) == 0);
	ATF_CHECK_ERRNO(EINVAL, mac_set_fd(p[0], label) == -1);
	mac_free(label);
}

IDLE_TC(p_a7_disabled_set,
    "P-A7: a rule in a disabled set does not apply until the set is enabled")
{
	struct lworker w;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	lworker_start(&w);
	(void)idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_READ);
	idle_set_range(ABAC_SYS_SET_DISABLE, IDLE_SET);
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_READ), "set disabled");
	idle_set_range(ABAC_SYS_SET_ENABLE, IDLE_SET);
	ATF_CHECK_EQ_MSG(EACCES, lworker_do(&w, LW_READ), "set enabled");
	lworker_stop(&w);
}

IDLE_TC(p_a8_rule_load_replaces,
    "P-A8: RULE_LOAD replacing deny-read by deny-exec applies at once")
{
	char buf[512];
	struct lworker w;
	size_t len;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	lworker_start(&w);
	(void)idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_READ);
	ATF_REQUIRE_EQ(EACCES, lworker_do(&w, LW_READ));
	len = idle_pack_rule(buf, sizeof(buf), ABAC_ACTION_DENY, ABAC_OP_EXEC,
	    IDLE_SET, SUBJ_LABEL, OBJ_LABEL);
	idle_load_rules(buf, len, 1);
	/* The loaded rule's id is unknown: the cleanup clears the table. */
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_READ), "read after the load");
	ATF_CHECK_EQ_MSG(EACCES, lworker_do(&w, LW_EXEC),
	    "exec after the load");
	lworker_stop(&w);
	idle_call(ABAC_SYS_RULE_CLEAR, NULL);
}

IDLE_TC(d_a1_unnamed_operation_evaluated,
    "D-A1: no rule, default allow: are stat(2) checks evaluated?")
{
	struct stat sb;
	uint64_t before, after;
	int i;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	before = idle_sysctl_u64("security.mac.mac_abac.checks");
	for (i = 0; i < 1000; i++)
		ATF_REQUIRE(stat(idle_obj, &sb) == 0);
	after = idle_sysctl_u64("security.mac.mac_abac.checks");
	printf("checks: %ju -> %ju\n", (uintmax_t)before, (uintmax_t)after);
#if ABAC_IDLE_GATED
	ATF_CHECK_EQ_MSG(before, after,
	    "%ju evaluations with no rule loaded",
	    (uintmax_t)(after - before));
#else
	ATF_CHECK_MSG(after - before >= 1000,
	    "only %ju evaluations for 1000 stat(2)",
	    (uintmax_t)(after - before));
#endif
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, p_a1_enforcing_no_rule);
	ATF_TP_ADD_TC(tp, p_a2_a3_rule_add_remove);
	ATF_TP_ADD_TC(tp, p_a4_default_deny_no_rule);
	ATF_TP_ADD_TC(tp, p_a5_label_attribute_protected);
	ATF_TP_ADD_TC(tp, p_a6_pipe_relabel);
	ATF_TP_ADD_TC(tp, p_a7_disabled_set);
	ATF_TP_ADD_TC(tp, p_a8_rule_load_replaces);
	ATF_TP_ADD_TC(tp, d_a1_unnamed_operation_evaluated);
	return (atf_no_error());
}
