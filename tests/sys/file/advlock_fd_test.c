/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * flock(2) and the fcntl(2) record locks are answered by the descriptor's
 * fileops (fo_advlock).  Vnode files take both; a FIFO takes flock(2) only;
 * descriptors whose table takes no locks (pipes, sockets, kqueues, shm,
 * pseudo-terminal masters, O_PATH) return EBADF from fcntl(2) and
 * EOPNOTSUPP from flock(2), as the type tests used to.  Lock semantics
 * themselves are covered by flock_test.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
whole_file(struct flock *fl, short type)
{
	memset(fl, 0, sizeof(*fl));
	fl->l_whence = SEEK_SET;
	fl->l_type = type;
}

/* The vnode answered: success, or anything but the type-test EBADF. */
static void
check_vnode_locks(int fd, bool writable)
{
	struct flock fl;

	whole_file(&fl, F_RDLCK);
	ATF_CHECK_EQ(0, fcntl(fd, F_SETLK, &fl));
	whole_file(&fl, F_WRLCK);
	ATF_CHECK_EQ(0, fcntl(fd, F_GETLK, &fl));
	if (writable) {
		whole_file(&fl, F_WRLCK);
		ATF_CHECK_EQ(0, fcntl(fd, F_SETLK, &fl));
	}
	whole_file(&fl, F_UNLCK);
	ATF_CHECK_EQ(0, fcntl(fd, F_SETLK, &fl));

	/* Open-file-description locks need the filesystem's support. */
	whole_file(&fl, F_RDLCK);
	errno = 0;
	if (fcntl(fd, F_OFD_SETLK, &fl) == 0) {
		whole_file(&fl, F_UNLCK);
		ATF_CHECK_EQ(0, fcntl(fd, F_OFD_SETLK, &fl));
	} else
		ATF_CHECK_EQ(EOPNOTSUPP, errno);

	ATF_CHECK_EQ(0, flock(fd, LOCK_SH | LOCK_NB));
	ATF_CHECK_EQ(0, flock(fd, LOCK_EX | LOCK_NB));
	ATF_CHECK_EQ(0, flock(fd, LOCK_UN));
}

static void
check_no_locks(int fd)
{
	struct flock fl;

	whole_file(&fl, F_RDLCK);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_SETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_GETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_OFD_SETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, flock(fd, LOCK_SH | LOCK_NB));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	check_vnode_locks(fd, true);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_vnode_locks(fd, false);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_vnode_locks(fd, true);
	close(fd);
}

/* A FIFO takes flock(2) and refuses the record locks with EBADF. */
ATF_TC_WITHOUT_HEAD(fifo);
ATF_TC_BODY(fifo, tc)
{
	struct flock fl;
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(0, flock(fd, LOCK_EX | LOCK_NB));
	ATF_CHECK_EQ(0, flock(fd, LOCK_UN));
	whole_file(&fl, F_RDLCK);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_SETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_GETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(opath_file);
ATF_TC_BODY(opath_file, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_no_locks(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(no_vnode);
ATF_TC_BODY(no_vnode, tc)
{
	int fds[2], fd;

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_no_locks(fds[0]);
	close(fds[0]);
	close(fds[1]);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_no_locks(fd);
	close(fd);
	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	check_no_locks(fd);
	close(fd);
	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	check_no_locks(fd);
	close(fd);
	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_no_locks(fd);
	close(fd);
	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_no_locks(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	struct flock fl;
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	whole_file(&fl, F_RDLCK);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_SETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, flock(fd, LOCK_SH));
	ATF_CHECK_EQ(EBADF, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, fifo);
	ATF_TP_ADD_TC(tp, opath_file);
	ATF_TP_ADD_TC(tp, no_vnode);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
