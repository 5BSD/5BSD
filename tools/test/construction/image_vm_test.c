/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
ATF_TC(image_roundtrip);
ATF_TC_HEAD(image_roundtrip, tc)
{
	atf_tc_set_md_var(tc, "descr", "Preserve complete filesystem observations through a UFS image");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
static void
run_image_test(const char *argument)
{
	pid_t child;
	int status;
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "/usr/local/bin/python3.12", "-I", "-S", "-B",
		    "/tests/image_roundtrip.py", argument, NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1)
		ATF_REQUIRE(errno == EINTR);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "image round trip failed, status %d", status);
}
ATF_TC_BODY(image_roundtrip, tc)
{
	(void)tc;
	run_image_test(NULL);
}
ATF_TC(unmount_order);
ATF_TC_HEAD(unmount_order, tc)
{
	atf_tc_set_md_var(tc, "descr", "Unmount UFS on tmpfs before clean VM shutdown");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(unmount_order, tc)
{
	(void)tc;
	run_image_test("--unmount-order");
}
ATF_TC(seed_readback);
ATF_TC_HEAD(seed_readback, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify GUID-bound seed state from a prior VM boot");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(seed_readback, tc)
{
	(void)tc;
	run_image_test("--seed-readback");
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, image_roundtrip);
	ATF_TP_ADD_TC(tp, unmount_order);
	ATF_TP_ADD_TC(tp, seed_readback);
	return atf_no_error();
}
