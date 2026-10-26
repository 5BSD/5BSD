/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

ATF_TC(ordinary_install);
ATF_TC_HEAD(ordinary_install, tc)
{
 atf_tc_set_md_var(tc, "descr", "Install complete explicit archives with actual hooks in disposable disk builder");
 atf_tc_set_md_var(tc, "timeout", "3600");
}
static void
run_fixture(const atf_tc_t *tc, const char *default_setup, const char *default_config)
{
 const char *python = atf_tc_get_config_var_wd(tc, "python", "/usr/local/bin/python3.12");
 const char *setup = atf_tc_get_config_var_wd(tc, "setup", default_setup);
 const char *config = atf_tc_get_config_var_wd(tc, "config", default_config);
 pid_t child, waited;
 int status;
 ATF_REQUIRE(geteuid() == 0);
 child = fork();
 ATF_REQUIRE(child >= 0);
 if (child == 0) {
  if (setenv("LD_LIBRARY_PATH", atf_tc_get_config_var_wd(tc,
      "bootstrap_library_path", "/usr/local/lib"), 1) != 0)
   _exit(126);
  execl(python, python, setup, "--config", config, (char *)NULL);
  _exit(127);
 }
 do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
 ATF_REQUIRE(waited == child);
 ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
     "builder fixture failed: status %#x; inspect retained disk report", status);
}
ATF_TC_BODY(ordinary_install, tc)
{
 run_fixture(tc, "/tests/bazel-builder/setup.py", "/tests/bazel-builder/settings.json");
}
ATF_TC(ordinary_port_build);
ATF_TC_HEAD(ordinary_port_build, tc)
{
 atf_tc_set_md_var(tc, "descr", "Build a maintained port in initialized disk builder with separate workspace and resource budgets");
 atf_tc_set_md_var(tc, "timeout", "3600");
}
ATF_TC_BODY(ordinary_port_build, tc)
{
 run_fixture(tc, "/tests/bazel-builder/build.py", "/tests/bazel-builder/build-settings.json");
}
ATF_TP_ADD_TCS(tp)
{
 ATF_TP_ADD_TC(tp, ordinary_install);
 ATF_TP_ADD_TC(tp, ordinary_port_build);
 return (atf_no_error());
}
