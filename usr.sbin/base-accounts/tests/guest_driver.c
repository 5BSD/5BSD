/* SPDX-License-Identifier: BSD-2-Clause */
/* Dedicated disposable-VM adapter; never mount or run its body on the host. */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

ATF_TC_WITH_CLEANUP(installed_paths);
ATF_TC_HEAD(installed_paths, tc)
{
	atf_tc_set_md_var(tc, "descr", "All original base-accounts cases at native installed guest paths");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "3600");
}
ATF_TC_BODY(installed_paths, tc)
{
	pid_t child;
	int status, ch;
	FILE *report;
	char type[] = "fstype", devfs[] = "devfs", path[] = "fspath",
	    destination[] = "/fixture/dev", tmpfs[] = "tmpfs", temporary[] = "/fixture/tmp",
	    size[] = "size", capacity[] = "16777216", mode[] = "mode", permissions[] = "1777";
	struct iovec iov[] = { { type, sizeof(type) }, { devfs, sizeof(devfs) },
	    { path, sizeof(path) }, { destination, sizeof(destination) } };
	struct iovec tmp[] = { { type, sizeof(type) }, { tmpfs, sizeof(tmpfs) },
	    { path, sizeof(path) }, { temporary, sizeof(temporary) },
	    { size, sizeof(size) }, { capacity, sizeof(capacity) },
	    { mode, sizeof(mode) }, { permissions, sizeof(permissions) } };

	(void)tc;
	ATF_REQUIRE_MSG(geteuid() == 0, "run only inside the disposable root VM");
	ATF_REQUIRE_MSG(nmount(iov, 4, 0) == 0, "mount guest fixture devfs: %s", strerror(errno));
	ATF_REQUIRE_MSG(nmount(tmp, 8, MNT_NOSUID) == 0,
	    "mount bounded guest fixture tmpfs: %s", strerror(errno));
	puts("BASE_ACCOUNTS_VM_TMPFS capacity_bytes=16777216 mode=1777");
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		char *const env[] = { "PATH=/usr/bin:/bin", "LC_ALL=C",
		    "PYTHONHOME=/runtime/python-home", "LD_LIBRARY_PATH=/runtime/python-libs",
		    "PYTHONDONTWRITEBYTECODE=1", NULL };
		char *const args[] = { "/runtime/python", "-B", "/runtime/guest_check.py",
		    "--root", "/fixture", "--manifest", "/runtime/fixture-manifest.json",
		    "--output", "/tmp/base-accounts-runtime-results.json", "--uid", "1001", "--gid", "1001",
		    "--profile", "/runtime/checker-profile.json", NULL };
		execve(args[0], args, env);
		perror("exec installed base-accounts runtime checker");
		_exit(127);
	}
	while (waitpid(child, &status, 0) < 0)
		ATF_REQUIRE_EQ(errno, EINTR);
	report = fopen("/tmp/base-accounts-runtime-results.json", "r");
	if (report != NULL) {
		puts("BASE_ACCOUNTS_RUNTIME_REPORT_BEGIN");
		while ((ch = fgetc(report)) != EOF)
			putchar(ch);
		puts("BASE_ACCOUNTS_RUNTIME_REPORT_END");
		fclose(report);
		fflush(stdout);
	}
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "checker failed, status %#x; inspect the retained serial report", status);
	ATF_REQUIRE_MSG(report != NULL, "checker did not produce a report");
}
ATF_TC_CLEANUP(installed_paths, tc)
{
	struct statfs fs;
	const char *paths[] = { "/fixture/tmp", "/fixture/dev" };
	int failed = 0;
	(void)tc;
	for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		if (statfs(paths[i], &fs) != 0 ||
		    (strcmp(fs.f_mntonname, paths[i]) == 0 && unmount(paths[i], 0) != 0)) {
			fprintf(stderr, "fixture cleanup %s: %s\n", paths[i], strerror(errno));
			failed = 1;
		}
	}
	if (failed)
		_exit(1);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, installed_paths);
	return (atf_no_error());
}
