/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * An empty path without AT_EMPTY_PATH is ENOENT, whatever the descriptor
 * names and whether or not the lookup runs lockless: namei() answers it
 * before it looks at the start directory.  Each case runs with
 * vfs.cache.param.fast_lookup on and off; whether lockless lookup was
 * actually in force (vfs.cache.param.fast_lookup_active, where the kernel
 * has it) is printed, since MAC policies with lookup hooks keep it off.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#define	FAST_LOOKUP		"vfs.cache.param.fast_lookup"
#define	FAST_LOOKUP_ACTIVE	"vfs.cache.param.fast_lookup_active"

static int saved = -1;

static void
set_fast_lookup(int v)
{
	size_t len;
	int old;

	len = sizeof(old);
	ATF_REQUIRE_MSG(sysctlbyname(FAST_LOOKUP, &old, &len, &v,
	    sizeof(v)) == 0, "set %s=%d: %s", FAST_LOOKUP, v, strerror(errno));
	if (saved == -1)
		saved = old;
}

static void
restore_fast_lookup(void)
{

	if (saved != -1)
		(void)sysctlbyname(FAST_LOOKUP, NULL, NULL, &saved,
		    sizeof(saved));
}

/* Cleanup runs in a process of its own: put back the default. */
static void
cleanup_fast_lookup(void)
{
	int v = 1;

	(void)sysctlbyname(FAST_LOOKUP, NULL, NULL, &v, sizeof(v));
}

static void
report_mode(int v)
{
	size_t len;
	int active;

	len = sizeof(active);
	if (sysctlbyname(FAST_LOOKUP_ACTIVE, &active, &len, NULL, 0) == 0)
		printf("%s=%d: lockless lookup %s\n", FAST_LOOKUP, v,
		    active ? "active" : "not active");
	else
		printf("%s=%d: %s not present\n", FAST_LOOKUP, v,
		    FAST_LOOKUP_ACTIVE);
}

static void
check_empty(int dfd, const char *what)
{
	int fd, mode;

	for (mode = 1; mode >= 0; mode--) {
		set_fast_lookup(mode);
		report_mode(mode);
		errno = 0;
		fd = openat(dfd, "", O_RDONLY);
		ATF_CHECK_MSG(fd == -1 && errno == ENOENT,
		    "%s, fast_lookup=%d: openat(\"\") returned %d errno %d "
		    "(%s), want ENOENT", what, mode, fd, errno,
		    strerror(errno));
		if (fd >= 0)
			close(fd);
	}
	restore_fast_lookup();
}

ATF_TC_WITH_CLEANUP(regular_file_fd);
ATF_TC_HEAD(regular_file_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "openat(regular file, \"\") is ENOENT, lockless or not");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(regular_file_fd, tc)
{
	int ffd;

	ffd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(ffd >= 0);
	check_empty(ffd, "regular file descriptor");
	close(ffd);
}
ATF_TC_CLEANUP(regular_file_fd, tc)
{

	cleanup_fast_lookup();
}

ATF_TC_WITH_CLEANUP(directory_fd);
ATF_TC_HEAD(directory_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "openat(directory, \"\") is ENOENT, lockless or not");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(directory_fd, tc)
{
	int dfd;

	ATF_REQUIRE(mkdir("dir", 0755) == 0);
	dfd = open("dir", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd >= 0);
	check_empty(dfd, "directory descriptor");
	close(dfd);
}
ATF_TC_CLEANUP(directory_fd, tc)
{

	cleanup_fast_lookup();
}

ATF_TC_WITH_CLEANUP(cwd_and_bad_fd);
ATF_TC_HEAD(cwd_and_bad_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "openat(AT_FDCWD or a closed descriptor, \"\") is ENOENT");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(cwd_and_bad_fd, tc)
{
	int badfd;

	check_empty(AT_FDCWD, "AT_FDCWD");
	badfd = open(".", O_RDONLY);
	ATF_REQUIRE(badfd >= 0);
	close(badfd);
	/* namei() answers "" before it looks up the descriptor. */
	check_empty(badfd, "closed descriptor");
}
ATF_TC_CLEANUP(cwd_and_bad_fd, tc)
{

	cleanup_fast_lookup();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, regular_file_fd);
	ATF_TP_ADD_TC(tp, directory_fd);
	ATF_TP_ADD_TC(tp, cwd_and_bad_fd);
	return (atf_no_error());
}
