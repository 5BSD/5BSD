/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * copy_file_range(2) is answered by the input descriptor's fileops
 * (fo_copy_file_range).  Two regular files copy; a descriptor that cannot
 * copy ranges on either side returns EINVAL, as the f_vnode tests did; the
 * generic checks (flags, direction, same-file overlap) keep their errnos.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
make_file(const char *name, const char *data, size_t len)
{
	int fd;

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, data, len));
	ATF_REQUIRE_EQ(0, lseek(fd, 0, SEEK_SET));
	return (fd);
}

ATF_TC_WITHOUT_HEAD(regular_files);
ATF_TC_BODY(regular_files, tc)
{
	char buf[32];
	off_t inoff, outoff;
	int in, out;

	in = make_file("in", "0123456789abcdef", 16);
	out = make_file("out", "", 0);
	/* Implicit offsets advance both files. */
	ATF_REQUIRE_EQ(8, copy_file_range(in, NULL, out, NULL, 8, 0));
	ATF_CHECK_EQ(8, lseek(in, 0, SEEK_CUR));
	ATF_CHECK_EQ(8, lseek(out, 0, SEEK_CUR));
	/* Explicit offsets leave the descriptors alone. */
	inoff = 12;
	outoff = 0;
	ATF_REQUIRE_EQ(4, copy_file_range(in, &inoff, out, &outoff, 4, 0));
	ATF_CHECK_EQ(16, inoff);
	ATF_CHECK_EQ(4, outoff);
	ATF_CHECK_EQ(8, lseek(in, 0, SEEK_CUR));
	ATF_REQUIRE_EQ(0, lseek(out, 0, SEEK_SET));
	ATF_REQUIRE_EQ(8, read(out, buf, sizeof(buf)));
	ATF_CHECK_EQ(0, memcmp(buf, "cdef4567", 8));
	/* EOF copies nothing. */
	inoff = 16;
	ATF_CHECK_EQ(0, copy_file_range(in, &inoff, out, NULL, 4, 0));
	close(in);
	close(out);
}

ATF_TC_WITHOUT_HEAD(same_file);
ATF_TC_BODY(same_file, tc)
{
	off_t inoff, outoff;
	int fd;

	fd = make_file("file", "0123456789abcdef", 16);
	/* Overlapping ranges are refused; disjoint ones copy. */
	inoff = 0;
	outoff = 4;
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(fd, &inoff, fd, &outoff, 8, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	inoff = 0;
	outoff = 8;
	ATF_CHECK_EQ(4, copy_file_range(fd, &inoff, fd, &outoff, 4, 0));
	/* Both implicit offsets on one file is refused. */
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(fd, NULL, fd, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(generic_checks);
ATF_TC_BODY(generic_checks, tc)
{
	off_t off;
	int in, out, ro;

	in = make_file("in", "0123456789abcdef", 16);
	out = make_file("out", "", 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(in, NULL, out, NULL, 4, 0x80000000));
	ATF_CHECK_EQ(EINVAL, errno);
	off = -1;
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(in, &off, out, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, copy_file_range(in, NULL, out, NULL, 0, 0));
	/* Direction: the output must be writable, the input readable. */
	ro = open("in", O_RDONLY);
	ATF_REQUIRE(ro >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(in, NULL, ro, NULL, 4, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(ro);
	close(in);
	close(out);
}

/* Anything that is not a vnode file is EINVAL on either side. */
ATF_TC_WITHOUT_HEAD(not_a_file);
ATF_TC_BODY(not_a_file, tc)
{
	int file, fds[2], sock, shm, fifo, fd;

	file = make_file("file", "0123456789abcdef", 16);
	ATF_REQUIRE_EQ(0, pipe(fds));
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(fds[0], NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(file, NULL, fds[1], NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	close(fds[0]);
	close(fds[1]);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(sock >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(file, NULL, sock, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	close(sock);

	shm = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(shm >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(shm, NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	close(shm);

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fifo = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fifo >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(fifo, NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(file, NULL, fifo, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	close(fifo);

	/* The mode checks come first: an O_PATH input has no FREAD. */
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(fd, NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);

	/* Readable types with no range copy: EINVAL after the mode checks. */
	fd = open("/dev/zero", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(fd, NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	close(fd);
	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(fd, NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	close(fd);
	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(fd, NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(file, NULL, fd, NULL, 4, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	close(fd);
	close(file);
}

/* A directory is a vnode file with nothing to copy: EISDIR, as before. */
ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int file, dir;

	file = make_file("file", "0123456789abcdef", 16);
	dir = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dir >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(dir, NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EISDIR, errno);
	close(dir);
	close(file);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	int file, closed;

	file = make_file("file", "0123456789abcdef", 16);
	closed = open("file", O_RDONLY);
	ATF_REQUIRE(closed >= 0);
	close(closed);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(closed, NULL, file, NULL, 4, 0));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, copy_file_range(file, NULL, closed, NULL, 4, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(file);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_files);
	ATF_TP_ADD_TC(tp, same_file);
	ATF_TP_ADD_TC(tp, generic_checks);
	ATF_TP_ADD_TC(tp, not_a_file);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
