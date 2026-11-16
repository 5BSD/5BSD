/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * getdirentries(2) is answered by the descriptor's fileops (fo_readdir).
 * Directories read entries; other vnode files return ENOTDIR; descriptors
 * with no vnode return EINVAL, as getvnode() did; O_PATH descriptors return
 * EBADF, as getvnode() did.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
check_errno(int fd, int expected)
{
	char buf[4096];
	off_t base;

	errno = 0;
	ATF_CHECK_EQ(-1, getdirentries(fd, buf, sizeof(buf), &base));
	ATF_CHECK_EQ(expected, errno);
}

/* The directory lists exactly its entries, and "." and ".." are among them. */
ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	char buf[8192], *p;
	struct dirent *d;
	off_t base;
	ssize_t n;
	int fd, dot, dotdot, a, b;

	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	ATF_REQUIRE_EQ(0, close(open("dir/a", O_WRONLY | O_CREAT, 0644)));
	ATF_REQUIRE_EQ(0, close(open("dir/b", O_WRONLY | O_CREAT, 0644)));
	fd = open("dir", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	dot = dotdot = a = b = 0;
	for (;;) {
		n = getdirentries(fd, buf, sizeof(buf), &base);
		ATF_REQUIRE_MSG(n >= 0, "getdirentries: %s", strerror(errno));
		if (n == 0)
			break;
		for (p = buf; p < buf + n; p += d->d_reclen) {
			d = (struct dirent *)(void *)p;
			if (d->d_fileno == 0)
				continue;
			if (strcmp(d->d_name, ".") == 0)
				dot++;
			else if (strcmp(d->d_name, "..") == 0)
				dotdot++;
			else if (strcmp(d->d_name, "a") == 0)
				a++;
			else if (strcmp(d->d_name, "b") == 0)
				b++;
			else
				atf_tc_fail("unexpected entry %s", d->d_name);
		}
	}
	ATF_CHECK_EQ(1, dot);
	ATF_CHECK_EQ(1, dotdot);
	ATF_CHECK_EQ(1, a);
	ATF_CHECK_EQ(1, b);
	/* At EOF the offset stays and a second read is still empty. */
	ATF_CHECK_EQ(0, getdirentries(fd, buf, sizeof(buf), &base));
	ATF_CHECK(lseek(fd, 0, SEEK_CUR) > 0);
	close(fd);
}

/* The system call rewinds nothing: lseek(0) reads the entries again. */
ATF_TC_WITHOUT_HEAD(rewind);
ATF_TC_BODY(rewind, tc)
{
	char buf[8192];
	off_t base;
	ssize_t first, again;
	int fd;

	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	fd = open("dir", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	first = getdirentries(fd, buf, sizeof(buf), &base);
	ATF_REQUIRE(first > 0);
	ATF_CHECK_EQ(0, base);
	ATF_CHECK_EQ(0, getdirentries(fd, buf, sizeof(buf), &base));
	ATF_REQUIRE_EQ(0, lseek(fd, 0, SEEK_SET));
	again = getdirentries(fd, buf, sizeof(buf), &base);
	ATF_CHECK_EQ(first, again);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, ENOTDIR);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(fifo);
ATF_TC_BODY(fifo, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, ENOTDIR);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, ENOTDIR);
	close(fd);
}

/* /dev/ptmx gives the master a vnode (a device: ENOTDIR); openpt none. */
ATF_TC_WITHOUT_HEAD(pts_master);
ATF_TC_BODY(pts_master, tc)
{
	int fd;

	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EINVAL);
	close(fd);
	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, ENOTDIR);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(opath_directory);
ATF_TC_BODY(opath_directory, tc)
{
	int fd;

	fd = open(".", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EBADF);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(no_vnode);
ATF_TC_BODY(no_vnode, tc)
{
	int fds[2], fd;

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_errno(fds[0], EINVAL);
	close(fds[0]);
	close(fds[1]);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EINVAL);
	close(fd);
	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EINVAL);
	close(fd);
	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EINVAL);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	int fd;

	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	check_errno(fd, EBADF);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, rewind);
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, fifo);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, pts_master);
	ATF_TP_ADD_TC(tp, opath_directory);
	ATF_TP_ADD_TC(tp, no_vnode);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
