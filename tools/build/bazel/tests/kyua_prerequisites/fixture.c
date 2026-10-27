/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
ATF_TC(missing_configuration);
ATF_TC_HEAD(missing_configuration, tc)
{
    atf_tc_set_md_var(tc, "require.config", "required_fixture_configuration");
}
ATF_TC_BODY(missing_configuration, tc)
{
    (void)tc;
    atf_tc_fail("prerequisite was ignored; this body must not run");
}
ATF_TC(ordinary_pass);
ATF_TC_HEAD(ordinary_pass, tc) { (void)tc; }
ATF_TC_BODY(ordinary_pass, tc) { (void)tc; ATF_REQUIRE(1); }
ATF_TC(intentional_failure);
ATF_TC_HEAD(intentional_failure, tc) { (void)tc; }
ATF_TC_BODY(intentional_failure, tc) { (void)tc; atf_tc_fail("controlled adapter failure"); }
ATF_TC(expected_failure);
ATF_TC_HEAD(expected_failure, tc) { (void)tc; }
ATF_TC_BODY(expected_failure, tc)
{
    (void)tc;
    atf_tc_expect_fail("controlled expected failure");
    ATF_REQUIRE(0);
}
ATF_TC(configuration);
ATF_TC_HEAD(configuration, tc)
{
    atf_tc_set_md_var(tc, "require.config", "selected_file scalar");
}
ATF_TC_BODY(configuration, tc)
{
    char line[128];
    const char *path = atf_tc_get_config_var(tc, "selected_file");
    FILE *file = fopen(path, "r");
    ATF_REQUIRE_MSG(file != NULL, "cannot open selected file: %s", path);
    ATF_REQUIRE(fgets(line, sizeof(line), file) != NULL);
    ATF_REQUIRE_STREQ("declared policy fixture\n", line);
    ATF_REQUIRE(fgetc(file) == EOF);
    ATF_REQUIRE(fclose(file) == 0);
    ATF_REQUIRE_STREQ("spaces ' \" $() = literal", atf_tc_get_config_var(tc, "scalar"));
}

static void
create_cleanup_marker(void)
{
    FILE *file = fopen("body.marker", "w");
    ATF_REQUIRE(file != NULL);
    ATF_REQUIRE(fclose(file) == 0);
}

static void
check_cleanup_marker(void)
{
    ATF_REQUIRE(access("body.marker", F_OK) == 0);
    fprintf(stderr, "KYUA_FIXTURE_CLEANUP_REACHED\n");
}

ATF_TC_WITH_CLEANUP(cleanup_pass);
ATF_TC_HEAD(cleanup_pass, tc) { (void)tc; }
ATF_TC_BODY(cleanup_pass, tc) { (void)tc; create_cleanup_marker(); }
ATF_TC_CLEANUP(cleanup_pass, tc) { (void)tc; check_cleanup_marker(); }

ATF_TC_WITH_CLEANUP(cleanup_failure);
ATF_TC_HEAD(cleanup_failure, tc) { (void)tc; }
ATF_TC_BODY(cleanup_failure, tc) { (void)tc; create_cleanup_marker(); }
ATF_TC_CLEANUP(cleanup_failure, tc)
{
    (void)tc; check_cleanup_marker();
    atf_tc_fail("controlled cleanup failure");
}

ATF_TC_WITH_CLEANUP(body_failure_cleanup);
ATF_TC_HEAD(body_failure_cleanup, tc) { (void)tc; }
ATF_TC_BODY(body_failure_cleanup, tc)
{
    (void)tc; create_cleanup_marker();
    atf_tc_fail("controlled body failure before cleanup");
}
ATF_TC_CLEANUP(body_failure_cleanup, tc) { (void)tc; check_cleanup_marker(); }

ATF_TC_WITH_CLEANUP(body_timeout_cleanup);
ATF_TC_HEAD(body_timeout_cleanup, tc) { atf_tc_set_md_var(tc, "timeout", "1"); }
ATF_TC_BODY(body_timeout_cleanup, tc)
{
    (void)tc; create_cleanup_marker();
    for (;;) pause();
}
ATF_TC_CLEANUP(body_timeout_cleanup, tc) { (void)tc; check_cleanup_marker(); }

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, missing_configuration);
    ATF_TP_ADD_TC(tp, ordinary_pass);
    ATF_TP_ADD_TC(tp, configuration);
    ATF_TP_ADD_TC(tp, expected_failure);
    ATF_TP_ADD_TC(tp, intentional_failure);
    ATF_TP_ADD_TC(tp, cleanup_pass);
    ATF_TP_ADD_TC(tp, cleanup_failure);
    ATF_TP_ADD_TC(tp, body_failure_cleanup);
    ATF_TP_ADD_TC(tp, body_timeout_cleanup);
    return atf_no_error();
}
