/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * msync(2) reaches the object's pager through pgo_sync.  A shared file
 * mapping writes back to the file (vnode pager); an anonymous mapping and a
 * private copy-on-write page have nothing to write back and the sync
 * succeeds (no pager method); MS_INVALIDATE after the write-back leaves the
 * file content intact.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int
make_file(const char *name, char fill)
{
	char buf[PAGE_SIZE];
	int fd;

	memset(buf, fill, sizeof(buf));
	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(buf), write(fd, buf, sizeof(buf)));
	return (fd);
}

static char
first_byte_on_disk(const char *name)
{
	char c;
	int fd;

	fd = open(name, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, read(fd, &c, 1));
	close(fd);
	return (c);
}

ATF_TC_WITHOUT_HEAD(shared_file_writeback);
ATF_TC_BODY(shared_file_writeback, tc)
{
	char *p;
	int fd;

	fd = make_file("file", 'a');
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	p[0] = 'b';
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC));
	ATF_CHECK_EQ('b', first_byte_on_disk("file"));
	p[0] = 'c';
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC | MS_INVALIDATE));
	ATF_CHECK_EQ('c', first_byte_on_disk("file"));
	/* The invalidated page faults back in with the written content. */
	ATF_CHECK_EQ('c', p[0]);
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_ASYNC));
	ATF_CHECK_EQ(0, munmap(p, PAGE_SIZE));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(private_file_copy);
ATF_TC_BODY(private_file_copy, tc)
{
	char *p;
	int fd;

	fd = make_file("file", 'a');
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	p[0] = 'b';
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC));
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC | MS_INVALIDATE));
	/* Private writes never reach the file and survive the sync. */
	ATF_CHECK_EQ('a', first_byte_on_disk("file"));
	ATF_CHECK_EQ('b', p[0]);
	ATF_CHECK_EQ(0, munmap(p, PAGE_SIZE));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(anonymous);
ATF_TC_BODY(anonymous, tc)
{
	char *p;

	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
	    -1, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	p[0] = 'a';
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC));
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC | MS_INVALIDATE));
	ATF_CHECK_EQ('a', p[0]);
	ATF_CHECK_EQ(0, munmap(p, PAGE_SIZE));
}

ATF_TC_WITHOUT_HEAD(unmapped_range);
ATF_TC_BODY(unmapped_range, tc)
{
	char *p;

	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
	    -1, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, munmap(p, PAGE_SIZE));
	errno = 0;
	ATF_CHECK_EQ(-1, msync(p, PAGE_SIZE, MS_SYNC));
	ATF_CHECK_EQ(ENOMEM, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, shared_file_writeback);
	ATF_TP_ADD_TC(tp, private_file_copy);
	ATF_TP_ADD_TC(tp, anonymous);
	ATF_TP_ADD_TC(tp, unmapped_range);
	return (atf_no_error());
}
