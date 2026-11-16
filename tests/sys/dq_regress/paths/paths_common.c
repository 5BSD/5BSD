/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared helpers of the path-syscall regression tests.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

void
pc_mkfile(const char *path, const char *text)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "create %s: %s", path, strerror(errno));
	if (text != NULL)
		ATF_REQUIRE(write(fd, text, strlen(text)) ==
		    (ssize_t)strlen(text));
	ATF_REQUIRE(close(fd) == 0);
}

void
pc_mkdir(const char *path)
{

	ATF_REQUIRE_MSG(mkdir(path, 0755) == 0, "mkdir %s: %s", path,
	    strerror(errno));
}

void
pc_symlink(const char *target, const char *path)
{

	ATF_REQUIRE_MSG(symlink(target, path) == 0, "symlink %s -> %s: %s",
	    path, target, strerror(errno));
}

void
pc_remove(const char *path)
{
	struct stat sb;

	if (lstat(path, &sb) != 0)
		return;
	(void)chflags(path, 0);
	if (S_ISDIR(sb.st_mode))
		(void)rmdir(path);
	else
		(void)unlink(path);
}

ino_t
pc_ino(const char *path, bool nofollow)
{
	struct stat sb;
	int error;

	error = nofollow ? lstat(path, &sb) : stat(path, &sb);
	ATF_REQUIRE_MSG(error == 0, "stat %s: %s", path, strerror(errno));
	return (sb.st_ino);
}

const char *
pc_unmapped(void)
{
	char *p;
	long pg;

	pg = sysconf(_SC_PAGESIZE);
	p = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE(p != MAP_FAILED);
	ATF_REQUIRE(munmap(p, (size_t)pg) == 0);
	/* Reserve it as a guard so nothing else is mapped there. */
	ATF_REQUIRE(mmap(p, (size_t)pg, PROT_NONE,
	    MAP_GUARD | MAP_FIXED, -1, 0) == p);
	return (p);
}

const char *
pc_straddle(const char *s, bool withnul)
{
	char *p, *start;
	size_t len;
	long pg;

	pg = sysconf(_SC_PAGESIZE);
	len = strlen(s);
	ATF_REQUIRE(len + 1 < (size_t)pg);
	p = mmap(NULL, 2 * (size_t)pg, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE(p != MAP_FAILED);
	/* The second page stays reserved and inaccessible. */
	ATF_REQUIRE(mprotect(p + pg, (size_t)pg, PROT_NONE) == 0);
	if (withnul) {
		start = p + pg - len - 1;
		memcpy(start, s, len + 1);
	} else {
		start = p + pg - len;
		memcpy(start, s, len);
	}
	return (start);
}

void
pc_longpath(char *buf, size_t len, const char *head, const char *tail)
{
	size_t hl, tl, i;

	hl = strlen(head);
	tl = strlen(tail);
	ATF_REQUIRE(hl + tl + 1 <= len);
	memcpy(buf, head, hl);
	for (i = hl; i < len - tl; i++)
		buf[i] = '/';
	memcpy(buf + len - tl, tail, tl);
	buf[len] = '\0';
}

void
pc_name(char *buf, size_t len, char c)
{

	memset(buf, c, len);
	buf[len] = '\0';
}

void
pc_symlink_chain(const char *prefix, int n, const char *target)
{
	char name[64], next[64];
	int i;

	for (i = 0; i < n; i++) {
		snprintf(name, sizeof(name), "%s%d", prefix, i);
		if (i == n - 1)
			pc_symlink(target, name);
		else {
			snprintf(next, sizeof(next), "%s%d", prefix, i + 1);
			pc_symlink(next, name);
		}
	}
}

bool
pc_sysctl_get(const char *name, int *valp)
{
	size_t len;

	len = sizeof(*valp);
	return (sysctlbyname(name, valp, &len, NULL, 0) == 0);
}

bool
pc_sysctl_set(const char *name, int val)
{

	return (sysctlbyname(name, NULL, NULL, &val, sizeof(val)) == 0);
}

bool
pc_is_root(void)
{

	return (geteuid() == 0);
}

int
pc_pipefd(void)
{
	int p[2];

	ATF_REQUIRE(pipe(p) == 0);
	return (p[0]);
}

int
pc_sockfd(void)
{
	int s;

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	return (s);
}

int
pc_dirent_count(const char *dir)
{
	DIR *d;
	struct dirent *de;
	int n;

	d = opendir(dir);
	ATF_REQUIRE(d != NULL);
	n = 0;
	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		n++;
	}
	closedir(d);
	return (n);
}
