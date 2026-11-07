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
#include <sys/wait.h>

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

/*
 * The descriptor refusal precedes argument validation and has no side
 * effects: a lockless type with a garbage lock type still gets EBADF from
 * fcntl(2) and EOPNOTSUPP from flock(2) with an empty operation, and the
 * F_GETFL view of the descriptor (FHASLOCK is not masked) is unchanged.
 */
static void
check_refused_before_args(int fd, int flock_errno)
{
	struct flock fl;
	int flags;

	flags = fcntl(fd, F_GETFL);
	ATF_REQUIRE(flags != -1);
	memset(&fl, 0, sizeof(fl));
	fl.l_type = 99;
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_SETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_GETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, flock(fd, 0));
	ATF_CHECK_EQ(flock_errno, errno);
	ATF_CHECK_EQ(flags, fcntl(fd, F_GETFL));
}

ATF_TC_WITHOUT_HEAD(refused_before_args);
ATF_TC_BODY(refused_before_args, tc)
{
	struct flock fl;
	int fds[2], fd;

	/*
	 * An anonymous pipe shares the FIFO table, which takes flock(2), so
	 * flock(pipe, 0) validates how (EBADF) before the pipe refuses.
	 */
	ATF_REQUIRE_EQ(0, pipe(fds));
	check_refused_before_args(fds[0], EBADF);
	/*
	 * A real flock(2) request on the pipe is EOPNOTSUPP, and the
	 * FHASLOCK bit set ahead of it comes off again (F_GETFL shows it).
	 */
	fd = fcntl(fds[0], F_GETFL);
	ATF_REQUIRE(fd != -1);
	errno = 0;
	ATF_CHECK_EQ(-1, flock(fds[0], LOCK_SH | LOCK_NB));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	ATF_CHECK_EQ(fd, fcntl(fds[0], F_GETFL));
	close(fds[0]);
	close(fds[1]);
	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	check_refused_before_args(fd, EOPNOTSUPP);
	close(fd);
	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_refused_before_args(fd, EOPNOTSUPP);
	close(fd);
	/* A FIFO takes flock(2) only: record locks refused first, same way. */
	ATF_REQUIRE_EQ(0, mkfifo("fifo2", 0644));
	fd = open("fifo2", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	memset(&fl, 0, sizeof(fl));
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_SETLK, &fl));
	ATF_CHECK_EQ(EBADF, errno);
	/* flock(2) with no operation on a FIFO: the argument check, EBADF. */
	errno = 0;
	ATF_CHECK_EQ(-1, flock(fd, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);
	/* A regular file validates how after accepting the descriptor. */
	fd = open("file", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, flock(fd, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);
}

/*
 * Closing any descriptor of a file releases the process's POSIX locks on
 * it, an O_PATH descriptor included.  The child holds the lock through
 * one descriptor, closes an O_PATH descriptor of the same file, and the
 * parent then finds the range unlocked.
 */
ATF_TC_WITHOUT_HEAD(close_releases_posix_locks);
ATF_TC_BODY(close_releases_posix_locks, tc)
{
	struct flock fl;
	int fd, to_parent[2], to_child[2], status;
	pid_t pid;
	char c;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, pipe(to_parent));
	ATF_REQUIRE_EQ(0, pipe(to_child));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int lfd, ofd;

		lfd = open("file", O_RDWR);
		whole_file(&fl, F_WRLCK);
		if (lfd < 0 || fcntl(lfd, F_SETLK, &fl) != 0)
			_exit(1);
		ofd = open("file", O_PATH);
		if (ofd < 0)
			_exit(2);
		close(ofd);
		/* Tell the parent, then wait to be told to exit. */
		if (write(to_parent[1], "x", 1) != 1)
			_exit(3);
		(void)read(to_child[0], &c, 1);
		_exit(0);
	}
	ATF_REQUIRE_EQ(1, read(to_parent[0], &c, 1));
	whole_file(&fl, F_WRLCK);
	ATF_REQUIRE_EQ(0, fcntl(fd, F_GETLK, &fl));
	ATF_CHECK_EQ_MSG(F_UNLCK, fl.l_type,
	    "the child's lock survived the close of its O_PATH descriptor");
	ATF_REQUIRE_EQ(1, write(to_child[1], "x", 1));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
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
	ATF_TP_ADD_TC(tp, refused_before_args);
	ATF_TP_ADD_TC(tp, close_releases_posix_locks);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
