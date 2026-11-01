/* SPDX-License-Identifier: BSD-2-Clause */
/* VM-only full-suite adapter; all filesystem mutations stay in fresh guest disks. */
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
command_status(char *const args[], char *const env[])
{
	pid_t child = fork();
	int status;
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		execve(args[0], args, env);
		perror(args[0]);
		_exit(127);
	}
	while (waitpid(child, &status, 0) < 0)
		ATF_REQUIRE_EQ(errno, EINTR);
	return (status);
}

static void
command(char *const args[], char *const env[])
{
	int status = command_status(args, env);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "%s failed: %#x", args[0], status);
}

ATF_TC_WITH_CLEANUP(full_suite);
ATF_TC_HEAD(full_suite, tc)
{
	atf_tc_set_md_var(tc, "descr", "Complete original makefs suite on fresh disk-backed guest storage");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "3600");
}
ATF_TC_BODY(full_suite, tc)
{
	char type[] = "fstype", path[] = "fspath", from[] = "from", ufs[] = "ufs",
	    devfs[] = "devfs", rw[] = "rw", root[] = "/", dev[] = "/fixture/dev", tmp[] = "/fixture/tmp";
	struct statfs fs;
	char device[64], trailing;
	FILE *stream;
	int ch;
	char *const env[] = { "PATH=/sbin:/bin:/usr/sbin:/usr/bin", "LC_ALL=C",
	    "PYTHONHOME=/runtime/python-home", "LD_LIBRARY_PATH=/runtime/python-libs",
	    "PYTHONDONTWRITEBYTECODE=1", NULL };

	(void)tc;
	ATF_REQUIRE_MSG(geteuid() == 0, "disposable guest root required");
	stream = fopen("/tests/scratch-device", "r");
	ATF_REQUIRE_MSG(stream != NULL, "explicit private scratch-device contract required");
	ATF_REQUIRE_EQ(fscanf(stream, "%63s %c", device, &trailing), 1);
	fclose(stream);
	ATF_REQUIRE_MSG(strncmp(device, "/dev/vtbd", 9) == 0,
	    "private virtio scratch-device contract required");
	ATF_REQUIRE_EQ(statfs("/", &fs), 0);
	ATF_REQUIRE_STREQ(fs.f_fstypename, "ufs");
	/* Ordinary writable OS state is needed by native account/PAM helpers. */
	struct iovec rootiov[] = { { type, sizeof(type) }, { ufs, sizeof(ufs) },
	    { path, sizeof(path) }, { root, sizeof(root) }, { from, sizeof(from) },
	    { fs.f_mntfromname, strlen(fs.f_mntfromname) + 1 }, { rw, sizeof(rw) }, { NULL, 0 } };
	ATF_REQUIRE_MSG(nmount(rootiov, 8, MNT_UPDATE) == 0,
	    "remount fresh guest root writable: %s", strerror(errno));
	ATF_REQUIRE_EQ(statfs("/", &fs), 0);
	ATF_REQUIRE((fs.f_flags & MNT_RDONLY) == 0);
	struct iovec deviov[] = { { type, sizeof(type) }, { devfs, sizeof(devfs) },
	    { path, sizeof(path) }, { dev, sizeof(dev) } };
	ATF_REQUIRE_MSG(nmount(deviov, 4, 0) == 0, "mount fixture devfs: %s", strerror(errno));
	char *const format[] = { "/usr/sbin/chroot", "/fixture", "/sbin/newfs",
	    "-U", "-i", "1048576", "-m", "0", device, NULL };
	command(format, env);
	struct iovec tmpiov[] = { { type, sizeof(type) }, { ufs, sizeof(ufs) },
	    { path, sizeof(path) }, { tmp, sizeof(tmp) }, { from, sizeof(from) },
	    { device, strlen(device) + 1 } };
	ATF_REQUIRE_MSG(nmount(tmpiov, 6, 0) == 0, "mount private disk scratch: %s", strerror(errno));
	char *const module[] = { "/usr/sbin/chroot", "/fixture", "/sbin/kldload",
	    "/boot/kernel/zfs.ko", NULL };
	char *const present[] = { "/usr/sbin/chroot", "/fixture", "/sbin/kldstat", "-m", "zfs", NULL };
	int existing = command_status(present, env);
	if (WIFEXITED(existing) && WEXITSTATUS(existing) == 0) {
		puts("MAKEFS_VM_ZFS provider=kernel-or-preloaded");
	} else {
		command(module, env);
		command(present, env);
		puts("MAKEFS_VM_ZFS provider=explicit-selected-kernel-module");
	}
	puts("MAKEFS_VM_STORAGE fresh_root_writable=1 scratch=disk-backed memory_disk=0");
	char *const checker[] = { "/runtime/python", "-B", "/runtime/makefs-runtime-check.py",
	    "--root", "/fixture", "--manifest", "/runtime/fixture-manifest.json",
	    "--inventory", "/fixture/tests/runtime_suite_inventory.json",
	    "--output", "/tmp/makefs-runtime-results.json",
	    "--profile", "/runtime/checker-profile.json", NULL };
	/* Print retained detail even on a failing checker. */
	pid_t child = fork();
	int status;
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		execve(checker[0], checker, env);
		perror(checker[0]);
		_exit(127);
	}
	while (waitpid(child, &status, 0) < 0)
		ATF_REQUIRE_EQ(errno, EINTR);
	stream = fopen("/tmp/makefs-runtime-results.json", "r");
	if (stream != NULL) {
		puts("MAKEFS_RUNTIME_REPORT_BEGIN");
		while ((ch = fgetc(stream)) != EOF)
			putchar(ch);
		puts("MAKEFS_RUNTIME_REPORT_END");
		fclose(stream);
		fflush(stdout);
	}
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "full suite checker failed: %#x; inspect retained serial report", status);
	ATF_REQUIRE(stream != NULL);
}
ATF_TC_CLEANUP(full_suite, tc)
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
	ATF_TP_ADD_TC(tp, full_suite);
	return (atf_no_error());
}
