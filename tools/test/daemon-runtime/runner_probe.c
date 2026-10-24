/* SPDX-License-Identifier: BSD-2-Clause */
/* Deliberately failing cases verify the VM runner, never product acceptance. */
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <atf-c.h>

ATF_TC_WITH_CLEANUP(cleanup_pass);
ATF_TC_HEAD(cleanup_pass, tc) { atf_tc_set_md_var(tc, "timeout", "5"); }
ATF_TC_BODY(cleanup_pass, tc) {
    int fd = open("body-state", O_CREAT | O_EXCL | O_WRONLY, 0600);
    (void)tc;
    ATF_REQUIRE(fd >= 0);
    ATF_REQUIRE_EQ(0, close(fd));
}
ATF_TC_CLEANUP(cleanup_pass, tc) {
    (void)tc;
    if (unlink("body-state") != 0) { perror("body state missing"); exit(1); }
    puts("RUNNER_PROBE_CLEANUP_EXECUTED");
}
ATF_TC_WITH_CLEANUP(cleanup_fail);
ATF_TC_HEAD(cleanup_fail, tc) { atf_tc_set_md_var(tc, "timeout", "5"); }
ATF_TC_BODY(cleanup_fail, tc) { (void)tc; }
ATF_TC_CLEANUP(cleanup_fail, tc) { (void)tc; fputs("deliberate cleanup failure\n", stderr); exit(1); }
ATF_TC_WITH_CLEANUP(body_fail);
ATF_TC_HEAD(body_fail, tc) { atf_tc_set_md_var(tc, "timeout", "5"); }
ATF_TC_BODY(body_fail, tc) { (void)tc; atf_tc_fail("deliberate body failure"); }
ATF_TC_CLEANUP(body_fail, tc) { (void)tc; puts("RUNNER_PROBE_FAILED_BODY_CLEANED"); }
ATF_TC_WITH_CLEANUP(body_timeout);
ATF_TC_HEAD(body_timeout, tc) { atf_tc_set_md_var(tc, "timeout", "1"); }
ATF_TC_BODY(body_timeout, tc) { (void)tc; for (;;) pause(); }
ATF_TC_CLEANUP(body_timeout, tc) { (void)tc; puts("RUNNER_PROBE_TIMED_OUT_BODY_CLEANED"); }
ATF_TP_ADD_TCS(tp) {
    ATF_TP_ADD_TC(tp, cleanup_pass);
    ATF_TP_ADD_TC(tp, cleanup_fail);
    ATF_TP_ADD_TC(tp, body_fail);
    ATF_TP_ADD_TC(tp, body_timeout);
    return atf_no_error();
}
