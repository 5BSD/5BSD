/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * msync(2) reaches the object's pager through pgo_sync.  The proof is the
 * page state seen through mincore(2), not the file's bytes (the unified
 * buffer cache returns a dirty mapped page with or without a sync): after a
 * write the page is MINCORE_MODIFIED, after MS_SYNC it is clean, after
 * MS_INVALIDATE it is gone from the object.  The file must live on a
 * filesystem with a vnode pager, so the test puts it under /var/tmp and
 * skips if that is tmpfs.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char path[] = "/var/tmp/msync_pager_test.XXXXXX";

/*
 * The file must keep its name: UFS does not write back the pages of a
 * removed inode, so an unlinked file would never show a clean page.  The
 * name is recorded in the work directory for the cleanup, which runs in
 * another process and would otherwise see only the template.
 */
static const char path_file[] = "msync_path";

static int
make_file(void)
{
	struct statfs sfs;
	char buf[PAGE_SIZE];
	FILE *f;
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE_MSG(fd >= 0, "mkstemp %s: %s", path, strerror(errno));
	f = fopen(path_file, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fprintf(f, "%s\n", path) > 0);
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_REQUIRE_EQ(0, fstatfs(fd, &sfs));
	if (strcmp(sfs.f_fstypename, "tmpfs") == 0)
		atf_tc_skip("/var/tmp is tmpfs; the vnode pager is not used");
	memset(buf, 'a', sizeof(buf));
	ATF_REQUIRE_EQ((ssize_t)sizeof(buf), write(fd, buf, sizeof(buf)));
	return (fd);
}

static void
cleanup_file(void)
{
	char name[sizeof(path)];
	FILE *f;

	f = fopen(path_file, "r");
	if (f == NULL)
		return;
	if (fgets(name, sizeof(name), f) != NULL) {
		name[strcspn(name, "\n")] = '\0';
		(void)unlink(name);
	}
	fclose(f);
}

static char
page_state(const void *p)
{
	char vec;

	ATF_REQUIRE_EQ(0, mincore(p, PAGE_SIZE, &vec));
	return (vec);
}

ATF_TC_WITH_CLEANUP(shared_file_writeback);
ATF_TC_HEAD(shared_file_writeback, tc)
{
	atf_tc_set_md_var(tc, "descr", "MS_SYNC cleans a dirty shared file "
	    "page, MS_INVALIDATE removes it, the file keeps the bytes");
}
ATF_TC_BODY(shared_file_writeback, tc)
{
	char *p, c;
	int fd;

	fd = make_file();
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	p[0] = 'b';
	ATF_CHECK((page_state(p) & MINCORE_INCORE) != 0);
	ATF_CHECK_MSG((page_state(p) & (MINCORE_MODIFIED |
	    MINCORE_MODIFIED_OTHER)) != 0, "the written page is not dirty");
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC));
	ATF_CHECK_MSG((page_state(p) & (MINCORE_MODIFIED |
	    MINCORE_MODIFIED_OTHER)) == 0, "MS_SYNC left the page dirty");
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC | MS_INVALIDATE));
	ATF_CHECK_MSG((page_state(p) & MINCORE_INCORE) == 0,
	    "MS_INVALIDATE left the page resident");
	/* The file has the write, and the page faults back in with it. */
	ATF_REQUIRE_EQ(1, pread(fd, &c, 1, 0));
	ATF_CHECK_EQ('b', c);
	ATF_CHECK_EQ('b', p[0]);
	ATF_CHECK_EQ(0, munmap(p, PAGE_SIZE));
	close(fd);
}
ATF_TC_CLEANUP(shared_file_writeback, tc)
{
	cleanup_file();
}

ATF_TC_WITH_CLEANUP(private_file_copy);
ATF_TC_HEAD(private_file_copy, tc)
{
	atf_tc_set_md_var(tc, "descr", "a private copy has no pager to "
	    "write back to and survives MS_SYNC and MS_INVALIDATE");
}
ATF_TC_BODY(private_file_copy, tc)
{
	char *p, c;
	int fd;

	fd = make_file();
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	p[0] = 'b';
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC));
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_SYNC | MS_INVALIDATE));
	/* The private copy keeps the write; the file never sees it. */
	ATF_CHECK_EQ('b', p[0]);
	ATF_REQUIRE_EQ(1, pread(fd, &c, 1, 0));
	ATF_CHECK_EQ('a', c);
	ATF_CHECK_EQ(0, munmap(p, PAGE_SIZE));
	close(fd);
}
ATF_TC_CLEANUP(private_file_copy, tc)
{
	cleanup_file();
}

/*
 * MS_INVALIDATE alone on a dirty shared page: the pager cleans it first
 * (OBJPC_SYNC | OBJPC_INVAL), so the file has the write and the page is
 * gone.  vm.old_msync only changes which pages the removal may drop, which
 * cannot be told apart from here once the clean has run; the knob is
 * exercised for its round trip.
 */
/*
 * The knob's old value is kept in the work directory so the cleanup can
 * restore it whatever the body did.
 */
static const char old_msync_file[] = "old_msync";

ATF_TC_WITH_CLEANUP(old_msync);
ATF_TC_HEAD(old_msync, tc)
{
	atf_tc_set_md_var(tc, "descr", "MS_INVALIDATE writes a dirty shared "
	    "page back before removing it, with vm.old_msync on or off");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(old_msync, tc)
{
	FILE *f;
	char *p, c;
	int fd, old, one;
	size_t len;

	len = sizeof(old);
	ATF_REQUIRE_EQ(0, sysctlbyname("vm.old_msync", &old, &len, NULL, 0));
	f = fopen(old_msync_file, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fprintf(f, "%d\n", old) > 0);
	ATF_REQUIRE_EQ(0, fclose(f));
	one = 1;
	ATF_REQUIRE_EQ(0, sysctlbyname("vm.old_msync", NULL, NULL, &one,
	    sizeof(one)));
	fd = make_file();
	p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	ATF_REQUIRE_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	p[0] = 'b';
	ATF_REQUIRE_EQ(0, msync(p, PAGE_SIZE, MS_INVALIDATE));
	ATF_CHECK((page_state(p) & MINCORE_INCORE) == 0);
	ATF_REQUIRE_EQ(1, pread(fd, &c, 1, 0));
	ATF_CHECK_EQ('b', c);
	ATF_CHECK_EQ(0, munmap(p, PAGE_SIZE));
	close(fd);
}
ATF_TC_CLEANUP(old_msync, tc)
{
	FILE *f;
	int old;

	cleanup_file();
	f = fopen(old_msync_file, "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%d", &old) == 1)
		(void)sysctlbyname("vm.old_msync", NULL, NULL, &old,
		    sizeof(old));
	fclose(f);
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
	/* No pager: nothing to write back; the page keeps its content. */
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
	ATF_TP_ADD_TC(tp, old_msync);
	ATF_TP_ADD_TC(tp, anonymous);
	ATF_TP_ADD_TC(tp, unmapped_range);
	return (atf_no_error());
}
