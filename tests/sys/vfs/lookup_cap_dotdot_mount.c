/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ".." from a start directory that is the root of a mounted file system.
 *
 * A strictly relative lookup (capability mode, O_RESOLVE_BENEATH, or a
 * descriptor whose rights are limited) may not leave its start directory.
 * When the start is the root of a mount, ".." is taken in the covered
 * directory of the file system below, and the start must still be the
 * limit: openat(mount_root, "..") is ENOTCAPABLE, as it is for any other
 * start.  Each case mounts its own file systems under its work directory.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	MOUNTS_FILE	"mounts"

static void
run(const char *cmd)
{
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
}

/* Mount fstype from source on target, remembering it for the cleanup. */
static void
mount_on(const char *fstype, const char *source, const char *target)
{
	char cmd[512];
	FILE *fp;

	snprintf(cmd, sizeof(cmd), "mount -t %s %s %s", fstype, source, target);
	run(cmd);
	fp = fopen(MOUNTS_FILE, "a");
	ATF_REQUIRE(fp != NULL);
	fprintf(fp, "%s\n", target);
	ATF_REQUIRE_EQ(0, fclose(fp));
}

/* Unmount in reverse order whatever the case mounted. */
static void
unmount_all(void)
{
	char lines[16][PATH_MAX];
	char cmd[PATH_MAX + 32];
	FILE *fp;
	int n;

	fp = fopen(MOUNTS_FILE, "r");
	if (fp == NULL)
		return;
	for (n = 0; n < 16 && fgets(lines[n], sizeof(lines[n]), fp) != NULL;
	    n++)
		lines[n][strcspn(lines[n], "\n")] = '\0';
	fclose(fp);
	while (n-- > 0) {
		snprintf(cmd, sizeof(cmd), "umount -f %s", lines[n]);
		(void)system(cmd);
	}
	(void)unlink(MOUNTS_FILE);
}

static void
set_sysctl(const char *name, int val)
{
	char path[64];
	FILE *fp;
	size_t len;
	int old;

	len = sizeof(old);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, &old, &len, NULL, 0),
	    "%s: %s", name, strerror(errno));
	snprintf(path, sizeof(path), "saved.%s", name);
	fp = fopen(path, "w");
	ATF_REQUIRE(fp != NULL);
	fprintf(fp, "%d\n", old);
	ATF_REQUIRE_EQ(0, fclose(fp));
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, NULL, NULL, &val,
	    sizeof(val)), "%s: %s", name, strerror(errno));
}

static void
restore_sysctl(const char *name)
{
	char path[64];
	FILE *fp;
	int old;

	snprintf(path, sizeof(path), "saved.%s", name);
	fp = fopen(path, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%d", &old) == 1)
		(void)sysctlbyname(name, NULL, NULL, &old, sizeof(old));
	fclose(fp);
	(void)unlink(path);
}

static void
cleanup(void)
{
	unmount_all();
	restore_sysctl("vfs.lookup_cap_dotdot");
	restore_sysctl("vfs.lookup_cap_dotdot_nonlocal");
}

/*
 * s/            the directory that holds the mount point
 * s/m           a tmpfs; s/m/x a directory in it, s/m/n a tmpfs on it
 * s/src, s/nl   a nullfs of s/src on s/nl
 */
static void
fixture(void)
{
	ATF_REQUIRE_EQ(0, mkdir("s", 0755));
	ATF_REQUIRE_EQ(0, mkdir("s/m", 0755));
	ATF_REQUIRE_EQ(0, mkdir("s/src", 0755));
	ATF_REQUIRE_EQ(0, mkdir("s/src/y", 0755));
	ATF_REQUIRE_EQ(0, mkdir("s/nl", 0755));
	mount_on("tmpfs", "tmpfs", "s/m");
	ATF_REQUIRE_EQ(0, mkdir("s/m/x", 0755));
	ATF_REQUIRE_EQ(0, mkdir("s/m/n", 0755));
	mount_on("tmpfs", "tmpfs", "s/m/n");
	mount_on("nullfs", "s/src", "s/nl");
}

enum mode { M_CAPMODE, M_BENEATH, M_LIMITED };

/*
 * In a child: from start, each path in denied must fail with ENOTCAPABLE
 * and each in allowed must open; the child reports the first difference.
 */
static void
check(enum mode mode, const char *start, const char * const *denied,
    const char * const *allowed)
{
	cap_rights_t rights;
	pid_t pid;
	int fd, flags, rfd, status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		fd = open(start, O_RDONLY | O_DIRECTORY);
		if (fd < 0)
			_exit(100);
		flags = O_RDONLY | O_DIRECTORY;
		if (mode == M_BENEATH)
			flags |= O_RESOLVE_BENEATH;
		if (mode == M_LIMITED || mode == M_CAPMODE) {
			cap_rights_init(&rights, CAP_LOOKUP, CAP_READ,
			    CAP_FSTAT, CAP_FCHDIR);
			if (cap_rights_limit(fd, &rights) != 0)
				_exit(101);
		}
		if (mode == M_CAPMODE && cap_enter() != 0)
			_exit(102);
		for (int i = 0; denied[i] != NULL; i++) {
			rfd = openat(fd, denied[i], flags);
			if (rfd >= 0 || errno != ENOTCAPABLE)
				_exit(1 + i);
		}
		for (int i = 0; allowed[i] != NULL; i++) {
			rfd = openat(fd, allowed[i], flags);
			if (rfd < 0)
				_exit(50 + i);
			close(rfd);
		}
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	switch (WEXITSTATUS(status)) {
	case 0:
		break;
	case 100: case 101: case 102:
		atf_tc_fail("%s: set-up step %d failed", start,
		    WEXITSTATUS(status));
		break;
	default:
		if (WEXITSTATUS(status) < 50)
			atf_tc_fail("%s: \"%s\" was not refused", start,
			    denied[WEXITSTATUS(status) - 1]);
		else
			atf_tc_fail("%s: \"%s\" was refused", start,
			    allowed[WEXITSTATUS(status) - 50]);
	}
}

static const char * const root_denied[] = { "..", "x/../..", "./..", NULL };
static const char * const root_allowed[] = { ".", "x/..", "x", NULL };
static const char * const nested_denied[] = { "..", "../..", NULL };
static const char * const nested_allowed[] = { ".", NULL };
static const char * const outer_denied[] = { "n/../..", NULL };
static const char * const outer_allowed[] = { "n/..", "n", NULL };
static const char * const null_denied[] = { "..", "y/../..", NULL };
static const char * const null_allowed[] = { "y/..", "y", NULL };
static const char * const plain_denied[] = { "..", NULL };
static const char * const plain_allowed[] = { "m/..", "m/x/../..", NULL };

static void
check_all(enum mode mode)
{
	/* The control: a start that is not a mount root. */
	check(mode, "s", plain_denied, plain_allowed);
	check(mode, "s/m", root_denied, root_allowed);
	check(mode, "s/m/n", nested_denied, nested_allowed);
	check(mode, "s/m", outer_denied, outer_allowed);
	check(mode, "s/nl", null_denied, null_allowed);
}

#define	MOUNT_CASE(name, descr, body)					\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "is.exclusive", "true");			\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	fixture();							\
	body;								\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	cleanup();							\
}

MOUNT_CASE(capmode_dotdot,
    "Capability mode with lookup_cap_dotdot=1: \"..\" does not leave a "
    "mount-root start",
    set_sysctl("vfs.lookup_cap_dotdot", 1); check_all(M_CAPMODE))
MOUNT_CASE(capmode_no_dotdot,
    "Capability mode with lookup_cap_dotdot=0: every \"..\" is refused",
    set_sysctl("vfs.lookup_cap_dotdot", 0);
    check(M_CAPMODE, "s/m", root_denied, (const char *[]){ ".", "x", NULL }))
MOUNT_CASE(capmode_dotdot_nonlocal,
    "lookup_cap_dotdot_nonlocal=0 changes nothing on local file systems",
    set_sysctl("vfs.lookup_cap_dotdot", 1);
    set_sysctl("vfs.lookup_cap_dotdot_nonlocal", 0); check_all(M_CAPMODE))
MOUNT_CASE(resolve_beneath,
    "O_RESOLVE_BENEATH: \"..\" does not leave a mount-root start",
    check_all(M_BENEATH))
MOUNT_CASE(limited_rights,
    "A rights-limited start descriptor: \"..\" does not leave a mount-root "
    "start",
    set_sysctl("vfs.lookup_cap_dotdot", 1); check_all(M_LIMITED))

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, capmode_dotdot);
	ATF_TP_ADD_TC(tp, capmode_no_dotdot);
	ATF_TP_ADD_TC(tp, capmode_dotdot_nonlocal);
	ATF_TP_ADD_TC(tp, resolve_beneath);
	ATF_TP_ADD_TC(tp, limited_rights);
	return (atf_no_error());
}
