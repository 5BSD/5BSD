/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fpathconf(2) is answered by the descriptor's fileops (fo_pathconf).
 * Every descriptor that carries a vnode must answer exactly as pathconf(2)
 * on its path does; pipes and sockets know only _PC_PIPE_BUF; descriptors
 * with no vnode return EOPNOTSUPP; _PC_ASYNC_IO is answered for every
 * descriptor.  The oracle is the kernel itself, so no fixtures are needed.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

static const int pc_names[] = {
	_PC_LINK_MAX, _PC_MAX_CANON, _PC_MAX_INPUT, _PC_NAME_MAX, _PC_PATH_MAX,
	_PC_PIPE_BUF, _PC_CHOWN_RESTRICTED, _PC_NO_TRUNC, _PC_VDISABLE,
	_PC_ALLOC_SIZE_MIN, _PC_FILESIZEBITS, _PC_REC_INCR_XFER_SIZE,
	_PC_REC_MAX_XFER_SIZE, _PC_REC_MIN_XFER_SIZE, _PC_REC_XFER_ALIGN,
	_PC_SYMLINK_MAX, _PC_ACL_EXTENDED, _PC_ACL_PATH_MAX, _PC_CAP_PRESENT,
	_PC_INF_PRESENT, _PC_MAC_PRESENT, _PC_ACL_NFS4, _PC_MIN_HOLE_SIZE,
	_PC_DEALLOC_PRESENT, _PC_NAMEDATTR_ENABLED, _PC_HAS_NAMEDATTR,
	_PC_HAS_HIDDENSYSTEM,
};

/*
 * fpathconf(fd) and pathconf(path) must agree, in value and in errno, for
 * every name, because both reach VOP_PATHCONF on the same vnode.
 */
static void
check_vnode_oracle(int fd, const char *path)
{
	long fv, pv;
	int ferr, perr;
	size_t i;

	for (i = 0; i < nitems(pc_names); i++) {
		errno = 0;
		pv = pathconf(path, pc_names[i]);
		perr = errno;
		errno = 0;
		fv = fpathconf(fd, pc_names[i]);
		ferr = errno;
		ATF_CHECK_EQ_MSG(pv, fv, "name %d: pathconf %ld fpathconf %ld",
		    pc_names[i], pv, fv);
		ATF_CHECK_EQ_MSG(perr, ferr, "name %d: pathconf errno %d "
		    "fpathconf errno %d", pc_names[i], perr, ferr);
	}
	ATF_CHECK_EQ(_POSIX_ASYNCHRONOUS_IO, fpathconf(fd, _PC_ASYNC_IO));
}

/* Anonymous pipes and sockets answer _PC_PIPE_BUF and nothing else. */
static void
check_pipe_buf_only(int fd)
{
	size_t i;

	ATF_CHECK_EQ(PIPE_BUF, fpathconf(fd, _PC_PIPE_BUF));
	ATF_CHECK_EQ(_POSIX_ASYNCHRONOUS_IO, fpathconf(fd, _PC_ASYNC_IO));
	for (i = 0; i < nitems(pc_names); i++) {
		if (pc_names[i] == _PC_PIPE_BUF)
			continue;
		errno = 0;
		ATF_CHECK_EQ(-1, fpathconf(fd, pc_names[i]));
		ATF_CHECK_EQ(EINVAL, errno);
	}
}

/* Descriptors with no vnode have no pathconf values at all. */
static void
check_unsupported(int fd)
{
	size_t i;

	ATF_CHECK_EQ(_POSIX_ASYNCHRONOUS_IO, fpathconf(fd, _PC_ASYNC_IO));
	for (i = 0; i < nitems(pc_names); i++) {
		errno = 0;
		ATF_CHECK_EQ(-1, fpathconf(fd, pc_names[i]));
		ATF_CHECK_EQ(EOPNOTSUPP, errno);
	}
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, "file");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, ".");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(opath_file);
ATF_TC_BODY(opath_file, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, "file");
	close(fd);
}

/* A FIFO is a pipe that carries a vnode: it answers as the vnode does. */
ATF_TC_WITHOUT_HEAD(fifo);
ATF_TC_BODY(fifo, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, "fifo");
	close(fd);
}

/* A character device under its own fileops answers as its vnode does. */
ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, "/dev/null");
	close(fd);
}

/*
 * A pseudo-terminal master is not a vnode descriptor but carries the
 * vnode it was opened through, and keeps answering through it.
 */
ATF_TC_WITHOUT_HEAD(pts_master);
ATF_TC_BODY(pts_master, tc)
{
	int fd;

	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(fpathconf(fd, _PC_MAX_CANON) >= 0);
	ATF_CHECK(fpathconf(fd, _PC_MAX_INPUT) >= 0);
	ATF_CHECK(fpathconf(fd, _PC_VDISABLE) >= 0);
	ATF_CHECK_EQ(_POSIX_ASYNCHRONOUS_IO, fpathconf(fd, _PC_ASYNC_IO));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(anonymous_pipe);
ATF_TC_BODY(anonymous_pipe, tc)
{
	int fds[2];

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_pipe_buf_only(fds[0]);
	check_pipe_buf_only(fds[1]);
	close(fds[0]);
	close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(socket);
ATF_TC_BODY(socket, tc)
{
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_pipe_buf_only(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(kqueue_fd);
ATF_TC_BODY(kqueue_fd, tc)
{
	int fd;

	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	check_unsupported(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(shm_fd);
ATF_TC_BODY(shm_fd, tc)
{
	int fd;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	check_unsupported(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	errno = 0;
	ATF_CHECK_EQ(-1, fpathconf(fd, _PC_NAME_MAX));
	ATF_CHECK_EQ(EBADF, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, opath_file);
	ATF_TP_ADD_TC(tp, fifo);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, pts_master);
	ATF_TP_ADD_TC(tp, anonymous_pipe);
	ATF_TP_ADD_TC(tp, socket);
	ATF_TP_ADD_TC(tp, kqueue_fd);
	ATF_TP_ADD_TC(tp, shm_fd);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
