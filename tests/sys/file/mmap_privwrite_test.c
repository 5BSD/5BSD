/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A MAP_PRIVATE mapping of a descriptor without the CAP_MMAP_W right may be
 * PROT_WRITE when the descriptor's fileops carry DFLAG_PRIVWRITE (the
 * writes are copy-on-write and never reach the object): vnode files, devfs
 * nodes and shm objects.  A MAP_SHARED PROT_WRITE mapping always needs the
 * right and a writable descriptor.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/mman.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void
limit_to_read(int fd)
{
	cap_rights_t rights;

	ATF_REQUIRE_EQ(0, cap_rights_limit(fd,
	    cap_rights_init(&rights, CAP_MMAP_R)));
}

static void
check_private_write(int fd)
{
	char *p;

	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	p[0] = 'x';
	ATF_CHECK_EQ('x', p[0]);
	ATF_CHECK_EQ(0, munmap(p, PAGE_SIZE));
}

static void
check_write_refused(int fd, int flags, int expected)
{
	char *p;

	errno = 0;
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, flags, fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, p);
	ATF_CHECK_EQ(expected, errno);
	if (p != MAP_FAILED)
		munmap(p, PAGE_SIZE);
}

/*
 * A run on a kernel from before the fix (kyua -v
 * test_suites.FreeBSD.base_panics=yes) skips the cases that panic it.
 */
static void
skip_on_base_panics(const atf_tc_t *tc)
{

	if (atf_tc_get_config_var_as_bool_wd(tc, "base_panics", false))
		atf_tc_skip("asserts on a kernel without the fix");
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	char buf[PAGE_SIZE];
	int fd;

	memset(buf, 'a', sizeof(buf));
	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(buf), write(fd, buf, sizeof(buf)));
	close(fd);
	fd = open("file", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	limit_to_read(fd);
	check_private_write(fd);
	check_write_refused(fd, MAP_SHARED, ENOTCAPABLE);
	close(fd);
	/* The private write never reached the file. */
	fd = open("file", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, read(fd, buf, 1));
	ATF_CHECK_EQ('a', buf[0]);
	check_write_refused(fd, MAP_SHARED, EACCES);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/zero", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	limit_to_read(fd);
	check_private_write(fd);
	check_write_refused(fd, MAP_SHARED, ENOTCAPABLE);
	close(fd);
}

/*
 * shm private mappings are copy-on-write too and carry DFLAG_PRIVWRITE:
 * a private write needs no CAP_MMAP_W, a shared one still does.
 */
ATF_TC_WITHOUT_HEAD(shm);
ATF_TC_BODY(shm, tc)
{
	int fd;

	skip_on_base_panics(tc);
	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, PAGE_SIZE));
	check_private_write(fd);
	limit_to_read(fd);
	check_private_write(fd);
	check_write_refused(fd, MAP_SHARED, ENOTCAPABLE);
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, shm);
	return (atf_no_error());
}
