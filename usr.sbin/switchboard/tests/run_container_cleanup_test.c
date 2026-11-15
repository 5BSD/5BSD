/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capsicum.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "run_container_cleanup.h"
#include "run_container_directory.h"

static int
run_directory(void)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkdir("run", 0700));
	fd = open("run", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

ATF_TC_WITHOUT_HEAD(nested_and_symlink);
ATF_TC_BODY(nested_and_symlink, tc)
{
	struct stat st;
	int parent, stale, child, next, sentinel, i;

	parent = run_directory();
	ATF_REQUIRE_EQ(0, mkdir("outside", 0700));
	sentinel = open("outside/keep", O_CREAT | O_EXCL | O_WRONLY, 0600);
	ATF_REQUIRE(sentinel >= 0);
	ATF_REQUIRE_EQ(4, write(sentinel, "keep", 4));
	close(sentinel);
	stale = sb_run_container_create(parent, "stale");
	ATF_REQUIRE(stale >= 0);
	ATF_REQUIRE_EQ(0, symlinkat("../../outside", stale, "escape"));
	/* Exercise stack growth without building or resolving long pathnames. */
	child = dup(stale);
	ATF_REQUIRE(child >= 0);
	for (i = 0; i < 80; i++) {
		ATF_REQUIRE_EQ(0, mkdirat(child, "nested", 0700));
		next = openat(child, "nested", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		ATF_REQUIRE(next >= 0);
		close(child);
		child = next;
	}
	sentinel = openat(child, "state", O_CREAT | O_EXCL | O_WRONLY, 0600);
	ATF_REQUIRE(sentinel >= 0);
	close(sentinel);
	close(child);
	ATF_REQUIRE_EQ(0, sb_run_container_sweep_at(parent));
	ATF_REQUIRE_ERRNO(ENOENT, fstatat(parent, "stale", &st, 0) == -1);
	ATF_REQUIRE_EQ(0, stat("outside/keep", &st));
	ATF_CHECK_EQ(4, st.st_size);
	/* The old held object is detached; restart creates a fresh container. */
	ATF_REQUIRE_EQ(0, fstat(stale, &st));
	ATF_CHECK_EQ(0, st.st_nlink);
	child = sb_run_container_create(parent, "stale");
	ATF_REQUIRE(child >= 0);
	close(child);
	close(stale);
	ATF_REQUIRE_EQ(0, sb_run_container_sweep_at(parent));
	ATF_REQUIRE_EQ(0, sb_run_container_sweep_at(parent));
	close(parent);
}

ATF_TC(failure_and_retry);
ATF_TC_HEAD(failure_and_retry, tc)
{
	atf_tc_set_md_var(tc, "descr", "Failed cleanup is reported; retry never adopts stale scratch");
}
ATF_TC_BODY(failure_and_retry, tc)
{
	struct stat before, after;
	int parent, stale, file, restricted;
	cap_rights_t rights;

	parent = run_directory();
	stale = sb_run_container_create(parent, "stale");
	ATF_REQUIRE(stale >= 0);
	ATF_REQUIRE_EQ(0, fstat(stale, &before));
	file = openat(stale, "state", O_CREAT | O_EXCL | O_WRONLY, 0600);
	ATF_REQUIRE(file >= 0);
	close(file);
	/* Actual kernel refusal, without requiring root or modifying file flags.
	 * A distinct description leaves the full-authority retry fd unchanged. */
	restricted = open("run", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(restricted >= 0);
	cap_rights_init(&rights, CAP_READ, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
	    CAP_SEEK);
	ATF_REQUIRE_EQ(0, cap_rights_limit(restricted, &rights));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    sb_run_container_sweep_at(restricted) == -1);
	ATF_REQUIRE_EQ(0, fstatat(parent, "stale", &after, 0));
	ATF_CHECK_EQ(before.st_ino, after.st_ino);
	ATF_REQUIRE_ERRNO(EEXIST, sb_run_container_create(parent, "stale") == -1);
	close(restricted);
	ATF_REQUIRE_EQ(0, sb_run_container_sweep_at(parent));
	ATF_REQUIRE_ERRNO(ENOENT, fstatat(parent, "stale", &after, 0) == -1);
	close(stale);
	stale = sb_run_container_create(parent, "stale");
	ATF_REQUIRE(stale >= 0);
	close(stale);
	close(parent);
}
ATF_TC_WITHOUT_HEAD(invalid_names);
ATF_TC_BODY(invalid_names, tc)
{
	const char *names[] = {"", ".", "..", "../outside", "/outside", "a/b"};
	int parent;
	size_t i;

	parent = run_directory();
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		ATF_REQUIRE_ERRNO(EINVAL, sb_run_container_remove_at(parent, names[i]) == -1);
	ATF_REQUIRE_EQ(0, sb_run_container_remove_at(parent, "absent"));
	close(parent);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nested_and_symlink);
	ATF_TP_ADD_TC(tp, failure_and_retry);
	ATF_TP_ADD_TC(tp, invalid_names);
	return (atf_no_error());
}
