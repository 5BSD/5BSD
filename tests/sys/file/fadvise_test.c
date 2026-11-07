/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * posix_fadvise(2) is answered by the descriptor's fileops (fo_fadvise)
 * once the system call has validated the range and advice and refused
 * unseekable descriptors with ESPIPE.  Regular files accept every advice;
 * other vnode files and descriptors without a vnode return ENODEV.
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

static const int advices[] = {
	POSIX_FADV_NORMAL, POSIX_FADV_SEQUENTIAL, POSIX_FADV_RANDOM,
	POSIX_FADV_WILLNEED, POSIX_FADV_DONTNEED, POSIX_FADV_NOREUSE,
};

static void
check_all_advice(int fd, int expected)
{
	size_t i;

	for (i = 0; i < nitems(advices); i++)
		ATF_CHECK_EQ_MSG(expected, posix_fadvise(fd, 0, 0, advices[i]),
		    "advice %d", advices[i]);
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(5, write(fd, "hello", 5));
	check_all_advice(fd, 0);
	/* Regions merge and trim; a second non-standard region is fine. */
	ATF_CHECK_EQ(0, posix_fadvise(fd, 0, 4096, POSIX_FADV_SEQUENTIAL));
	ATF_CHECK_EQ(0, posix_fadvise(fd, 4096, 4096, POSIX_FADV_SEQUENTIAL));
	ATF_CHECK_EQ(0, posix_fadvise(fd, 0, 8192, POSIX_FADV_NORMAL));
	ATF_CHECK_EQ(0, posix_fadvise(fd, 100, 100, POSIX_FADV_RANDOM));
	ATF_CHECK_EQ(0, posix_fadvise(fd, 0, 50, POSIX_FADV_NORMAL));
	ATF_CHECK_EQ(0, posix_fadvise(fd, 150, 100, POSIX_FADV_NORMAL));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(invalid_arguments);
ATF_TC_BODY(invalid_arguments, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(EINVAL, posix_fadvise(fd, -1, 0, POSIX_FADV_NORMAL));
	ATF_CHECK_EQ(EINVAL, posix_fadvise(fd, 0, -1, POSIX_FADV_NORMAL));
	ATF_CHECK_EQ(EINVAL, posix_fadvise(fd, OFF_MAX, 1, POSIX_FADV_NORMAL));
	ATF_CHECK_EQ(EINVAL, posix_fadvise(fd, 0, 0, 12345));
	close(fd);
}

/* Directories and devices are vnode files with nothing to advise about. */
ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_all_advice(fd, ENODEV);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_all_advice(fd, ENODEV);
	close(fd);
}

/* shm is seekable but has no vnode: ENODEV, as before. */
ATF_TC_WITHOUT_HEAD(shm_fd);
ATF_TC_BODY(shm_fd, tc)
{
	int fd;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	check_all_advice(fd, ENODEV);
	close(fd);
}

/* Unseekable descriptors never reach the table. */
ATF_TC_WITHOUT_HEAD(unseekable);
ATF_TC_BODY(unseekable, tc)
{
	int fds[2], fd;

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_all_advice(fds[0], ESPIPE);
	close(fds[0]);
	close(fds[1]);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_all_advice(fd, ESPIPE);
	close(fd);

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_all_advice(fd, ESPIPE);
	close(fd);

	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	check_all_advice(fd, ESPIPE);
	close(fd);

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_all_advice(fd, ESPIPE);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(EBADF, posix_fadvise(fd, 0, 0, POSIX_FADV_NORMAL));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, invalid_arguments);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, shm_fd);
	ATF_TP_ADD_TC(tp, unseekable);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
