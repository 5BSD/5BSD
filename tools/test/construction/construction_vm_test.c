/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/procctl.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

ATF_TC(execution);
ATF_TC_HEAD(execution, tc)
{

	atf_tc_set_md_var(tc, "descr", "Real construction jail, generator and descendant cleanup");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "240");
}
ATF_TC_BODY(execution, tc)
{
	pid_t child, waited;
	int status;

	(void)tc;
	/* Reap orphaned jail workers while Python waits for jail destruction. */
	ATF_REQUIRE(procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/construction_vm.py", NULL);
		_exit(127);
	}
	for (;;) {
		waited = waitpid(-1, &status, 0);
		if (waited == -1 && errno == EINTR)
			continue;
		ATF_REQUIRE(waited > 0);
		if (waited == child)
			break;
	}
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "construction VM tests failed, wait status %d", status);
}
ATF_TC(boot_environments);
ATF_TC_HEAD(boot_environments, tc)
{
	atf_tc_set_md_var(tc, "descr", "Private ZFS boot-environment clone and removal mechanics");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(boot_environments, tc)
{
	pid_t child;
	int status;

	(void)tc;
	ATF_REQUIRE(system("/sbin/kldload -n /boot/kernel/zfs.ko") == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/be_vm_test.py", "--disposable-vm",
		    "--helper", "/tests/deploy.py", "--work-root", "/tmp", NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1) {
		ATF_REQUIRE(errno == EINTR);
	}
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "boot-environment tests failed, wait status %d", status);
}
ATF_TC(pkg_registration);
ATF_TC_HEAD(pkg_registration, tc)
{
	atf_tc_set_md_var(tc, "descr", "Jailed pkg registration hook controls and payload preservation");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(pkg_registration, tc)
{
	pid_t child, waited;
	int status;

	(void)tc;
	ATF_REQUIRE(procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/pkg_registration.py", "--disposable-vm",
		    "--pkg", "/tests/pkg-static", "--shell-closure", "/tests/shell-closure.json",
		    "--work", "/tmp/pkg-registration", "--identity", "/tests/pkg-identity.json", NULL);
		_exit(127);
	}
	for (;;) {
		waited = waitpid(-1, &status, 0);
		if (waited == -1 && errno == EINTR)
			continue;
		ATF_REQUIRE(waited > 0);
		if (waited == child)
			break;
	}
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "pkg registration tests failed, wait status %d", status);
}
ATF_TC(system_database);
ATF_TC_HEAD(system_database, tc)
{
	atf_tc_set_md_var(tc, "descr", "Construct and verify an explicit full selected package database");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "1200");
}
static void
run_system_construction(const char *mode, int retained)
{
	pid_t child, waited;
	int status;
	ATF_REQUIRE(procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    (retained ? "/tests/retained_system.py" : "/tests/system_database.py"),
		    "--disposable-vm", (retained ? "--settings" : "--work"),
		    (retained ? "/tests/builder-work.json" : "/tmp/system-database"), mode, NULL);
		_exit(127);
	}
	for (;;) {
		waited = waitpid(-1, &status, 0);
		if (waited == -1 && errno == EINTR)
			continue;
		ATF_REQUIRE(waited > 0);
		if (waited == child)
			break;
	}
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "system database construction failed, wait status %d", status);
}
ATF_TC_BODY(system_database, tc)
{
	(void)tc;
	run_system_construction("--database-only", 0);
}
ATF_TC(system_filesystem);
ATF_TC_HEAD(system_filesystem, tc)
{
	atf_tc_set_md_var(tc, "descr", "Extract and reconcile a complete selected filesystem and declared generators");
	atf_tc_set_md_var(tc, "require.user", "root");
	/* Full payload scans after each generator exceed database-only work. */
	atf_tc_set_md_var(tc, "timeout", "3600");
}
ATF_TC_BODY(system_filesystem, tc)
{
	(void)tc;
	run_system_construction("--filesystem", 0);
}
ATF_TC(retained_system_filesystem);
ATF_TC_HEAD(retained_system_filesystem, tc)
{
	atf_tc_set_md_var(tc, "descr", "Complete selected filesystem construction on a retained private disk");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "3600");
}
ATF_TC_BODY(retained_system_filesystem, tc)
{
	(void)tc;
	run_system_construction("--filesystem", 1);
}
ATF_TC(builder_storage);
ATF_TC_HEAD(builder_storage, tc)
{
	atf_tc_set_md_var(tc, "descr", "Private disk-backed builder workspace and unsafe-path refusals");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(builder_storage, tc)
{
	pid_t child;
	int status;
	(void)tc;
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/builder_storage_test.py", NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1)
		ATF_REQUIRE(errno == EINTR);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "builder storage failed, wait status %d", status);
}
static void
run_retained_verification(const char *mode)
{
	pid_t child;
	int status;
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/verify_retained_vm.py", mode, NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1)
		ATF_REQUIRE(errno == EINTR);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "retained verification failed, wait status %d", status);
}
ATF_TC(retained_verify);
ATF_TC_HEAD(retained_verify, tc)
{
	atf_tc_set_md_var(tc, "descr", "Independent post-shutdown retained system consistency");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "1800");
}
ATF_TC_BODY(retained_verify, tc) { (void)tc; run_retained_verification("--verify"); }
ATF_TC(retained_incomplete);
ATF_TC_HEAD(retained_incomplete, tc)
{
	atf_tc_set_md_var(tc, "descr", "Read-only artifact mount and incomplete-output refusal");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(retained_incomplete, tc) { (void)tc; run_retained_verification("--expect-incomplete"); }
ATF_TC(retained_state_initialize);
ATF_TC_HEAD(retained_state_initialize, tc)
{
	atf_tc_set_md_var(tc, "descr", "Initialize copied state datasets from a verified retained generation");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "3600");
}
ATF_TC_BODY(retained_state_initialize, tc)
{
	(void)tc;
	ATF_REQUIRE(system("/sbin/kldload -n /boot/kernel/zfs.ko") == 0);
	run_retained_verification("--initialize-state");
}
ATF_TC(retained_image);
ATF_TC_HEAD(retained_image, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify retained generation, materialize and export its complete UFS image");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "3600");
}
ATF_TC_BODY(retained_image, tc) { (void)tc; run_retained_verification("--image"); }
ATF_TC(state_allocation);
ATF_TC_HEAD(state_allocation, tc)
{
	atf_tc_set_md_var(tc, "descr", "Allocate explicit generation state on a fresh private disk");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(state_allocation, tc)
{
	pid_t child;
	int status;
	(void)tc;
	puts("STATE_ALLOCATION_MODULE start");
	fflush(stdout);
	ATF_REQUIRE(system("/sbin/kldload -n /boot/kernel/zfs.ko") == 0);
	puts("STATE_ALLOCATION_MODULE complete");
	fflush(stdout);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/state_allocation.py", NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1)
		ATF_REQUIRE(errno == EINTR);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "state allocation failed, status %d", status);
}
ATF_TC(state_readback);
ATF_TC_HEAD(state_readback, tc)
{
	atf_tc_set_md_var(tc, "descr", "Read back allocation identities from a read-only private disk");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(state_readback, tc)
{
	pid_t child;
	int status;
	(void)tc;
	ATF_REQUIRE(system("/sbin/kldload -n /boot/kernel/zfs.ko") == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/state_readback.py", NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1)
		ATF_REQUIRE(errno == EINTR);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "state readback failed, status %d", status);
}
ATF_TC(state_provider_allocation);
ATF_TC_HEAD(state_provider_allocation, tc)
{
	atf_tc_set_md_var(tc, "descr", "Allocate provider storage on a private copy of the ordinary state disk");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(state_provider_allocation, tc)
{
	pid_t child;
	int status;
	(void)tc;
	ATF_REQUIRE(system("/sbin/kldload -n /boot/kernel/zfs.ko") == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/state_provider_allocation.py", NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1)
		ATF_REQUIRE(errno == EINTR);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "state readback failed, status %d", status);
}
ATF_TC(installation_policy);
ATF_TC_HEAD(installation_policy, tc)
{
	atf_tc_set_md_var(tc, "descr", "Real private-root installation and relocation transactions");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(installation_policy, tc)
{
	pid_t child;
	int status;
	(void)tc;
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0 ||
		    setenv("BSD_BUILD_CONSTRUCTION_HELPER", "/tests/construction.py", 1) != 0 ||
		    setenv("BSD_BUILD_RETAINED_HELPER", "/tests/verify_retained.py", 1) != 0)
			_exit(126);
		execl("/usr/local/bin/python3.12", "python3.12", "-I", "-S", "-B",
		    "/tests/installation_policy_test.py", "-v", NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1)
		ATF_REQUIRE(errno == EINTR);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "installation policy tests failed, status %d", status);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, installation_policy);
	ATF_TP_ADD_TC(tp, state_provider_allocation);
	ATF_TP_ADD_TC(tp, state_readback);
	ATF_TP_ADD_TC(tp, state_allocation);
	ATF_TP_ADD_TC(tp, execution);
	ATF_TP_ADD_TC(tp, retained_verify);
	ATF_TP_ADD_TC(tp, retained_state_initialize);
	ATF_TP_ADD_TC(tp, retained_image);
	ATF_TP_ADD_TC(tp, retained_incomplete);
	ATF_TP_ADD_TC(tp, builder_storage);
	ATF_TP_ADD_TC(tp, system_database);
	ATF_TP_ADD_TC(tp, system_filesystem);
	ATF_TP_ADD_TC(tp, retained_system_filesystem);
	ATF_TP_ADD_TC(tp, pkg_registration);
	ATF_TP_ADD_TC(tp, boot_environments);
	return (atf_no_error());
}
