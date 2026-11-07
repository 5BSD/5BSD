/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The extattr_*_fd(2) family is answered by the descriptor's fileops
 * (fo_extattr).  A vnode file answers as the same call on its path does,
 * whether the filesystem supports extended attributes or not; descriptors
 * with no vnode return EINVAL, as getvnode_path() did; O_PATH descriptors
 * are accepted, as getvnode_path() did.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/extattr.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	NS	EXTATTR_NAMESPACE_USER
#define	NAME	"fileops-test"

/* Every fd form and its path form agree in result and errno. */
static void
check_oracle(int fd, const char *path)
{
	char fbuf[64], pbuf[64];
	ssize_t fr, pr;
	int ferr, perr;

	errno = 0;
	pr = extattr_set_file(path, NS, NAME, "value", 5);
	perr = errno;
	errno = 0;
	fr = extattr_set_fd(fd, NS, NAME, "value", 5);
	ferr = errno;
	ATF_CHECK_EQ_MSG(pr, fr, "set: %zd vs %zd", pr, fr);
	ATF_CHECK_EQ_MSG(perr, ferr, "set: errno %d vs %d", perr, ferr);

	errno = 0;
	pr = extattr_get_file(path, NS, NAME, pbuf, sizeof(pbuf));
	perr = errno;
	errno = 0;
	fr = extattr_get_fd(fd, NS, NAME, fbuf, sizeof(fbuf));
	ferr = errno;
	ATF_CHECK_EQ_MSG(pr, fr, "get: %zd vs %zd", pr, fr);
	ATF_CHECK_EQ_MSG(perr, ferr, "get: errno %d vs %d", perr, ferr);
	if (pr > 0 && fr == pr)
		ATF_CHECK_EQ(0, memcmp(pbuf, fbuf, pr));

	/* A NULL buffer asks for the size. */
	errno = 0;
	pr = extattr_get_file(path, NS, NAME, NULL, 0);
	perr = errno;
	errno = 0;
	fr = extattr_get_fd(fd, NS, NAME, NULL, 0);
	ferr = errno;
	ATF_CHECK_EQ_MSG(pr, fr, "size: %zd vs %zd", pr, fr);
	ATF_CHECK_EQ_MSG(perr, ferr, "size: errno %d vs %d", perr, ferr);

	errno = 0;
	pr = extattr_list_file(path, NS, pbuf, sizeof(pbuf));
	perr = errno;
	errno = 0;
	fr = extattr_list_fd(fd, NS, fbuf, sizeof(fbuf));
	ferr = errno;
	ATF_CHECK_EQ_MSG(pr, fr, "list: %zd vs %zd", pr, fr);
	ATF_CHECK_EQ_MSG(perr, ferr, "list: errno %d vs %d", perr, ferr);
	if (pr > 0 && fr == pr)
		ATF_CHECK_EQ(0, memcmp(pbuf, fbuf, pr));

	errno = 0;
	pr = extattr_delete_file(path, NS, NAME);
	perr = errno;
	/* The path form may already have removed it; recreate for the fd. */
	(void)extattr_set_fd(fd, NS, NAME, "value", 5);
	errno = 0;
	fr = extattr_delete_fd(fd, NS, NAME);
	ferr = errno;
	ATF_CHECK_EQ_MSG(pr, fr, "delete: %zd vs %zd", pr, fr);
	ATF_CHECK_EQ_MSG(perr, ferr, "delete: errno %d vs %d", perr, ferr);
}

static void
check_no_vnode(int fd)
{
	char buf[64];

	errno = 0;
	ATF_CHECK_EQ(-1, extattr_set_fd(fd, NS, NAME, "value", 5));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, extattr_get_fd(fd, NS, NAME, buf, sizeof(buf)));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, extattr_delete_fd(fd, NS, NAME));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, extattr_list_fd(fd, NS, buf, sizeof(buf)));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	check_oracle(fd, "file");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	fd = open("dir", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_oracle(fd, "dir");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(opath_file);
ATF_TC_BODY(opath_file, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_oracle(fd, "file");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(fifo);
ATF_TC_BODY(fifo, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_oracle(fd, "fifo");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_oracle(fd, "/dev/null");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(pts_master);
ATF_TC_BODY(pts_master, tc)
{
	int fd;

	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_no_vnode(fd);
	close(fd);
	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_oracle(fd, "/dev/ptmx");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(no_vnode);
ATF_TC_BODY(no_vnode, tc)
{
	int fds[2], fd;

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_no_vnode(fds[0]);
	close(fds[0]);
	close(fds[1]);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_no_vnode(fd);
	close(fd);
	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	check_no_vnode(fd);
	close(fd);
	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	check_no_vnode(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	char buf[64];
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	errno = 0;
	ATF_CHECK_EQ(-1, extattr_get_fd(fd, NS, NAME, buf, sizeof(buf)));
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
	ATF_TP_ADD_TC(tp, no_vnode);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
