/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * A MAP_PRIVATE mapping of a read-only descriptor may be PROT_WRITE when
 * the descriptor's fileops carry DFLAG_PRIVWRITE (the writes are
 * copy-on-write and never reach the file): vnode files and devfs nodes.
 * Other types keep needing a writable descriptor, and MAP_SHARED always
 * does.
 */

#include <sys/param.h>
#include <sys/mman.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

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
check_shared_write_refused(int fd)
{
	char *p;

	errno = 0;
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, p);
	ATF_CHECK_EQ(EACCES, errno);
	if (p != MAP_FAILED)
		munmap(p, PAGE_SIZE);
}

ATF_TC_WITHOUT_HEAD(regular_file_readonly);
ATF_TC_BODY(regular_file_readonly, tc)
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
	check_private_write(fd);
	check_shared_write_refused(fd);
	close(fd);
	/* The private write never reached the file. */
	fd = open("file", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, read(fd, buf, 1));
	ATF_CHECK_EQ('a', buf[0]);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node_readonly);
ATF_TC_BODY(devfs_node_readonly, tc)
{
	int fd;

	fd = open("/dev/zero", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	check_private_write(fd);
	check_shared_write_refused(fd);
	close(fd);
}

/* shm has no DFLAG_PRIVWRITE: a read-only shm fd refuses PROT_WRITE. */
ATF_TC_WITHOUT_HEAD(shm_readonly);
ATF_TC_BODY(shm_readonly, tc)
{
	char *p;
	int fd, rofd;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, PAGE_SIZE));
	rofd = open("/dev/null", O_RDONLY);	/* placeholder slot */
	ATF_REQUIRE(rofd >= 0);
	close(rofd);
	/* Re-open the same object read-only through /dev/fd is not possible
	 * for SHM_ANON; use a named object instead. */
	close(fd);
	shm_unlink("/mmap_privwrite_test");
	fd = shm_open("/mmap_privwrite_test", O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, PAGE_SIZE));
	rofd = shm_open("/mmap_privwrite_test", O_RDONLY, 0);
	ATF_REQUIRE(rofd >= 0);
	errno = 0;
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, rofd, 0);
	ATF_CHECK_EQ(MAP_FAILED, p);
	ATF_CHECK_EQ(EACCES, errno);
	if (p != MAP_FAILED)
		munmap(p, PAGE_SIZE);
	close(rofd);
	close(fd);
	shm_unlink("/mmap_privwrite_test");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file_readonly);
	ATF_TP_ADD_TC(tp, devfs_node_readonly);
	ATF_TP_ADD_TC(tp, shm_readonly);
	return (atf_no_error());
}
