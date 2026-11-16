/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The __acl_*_fd(2) family is answered by the descriptor's fileops
 * (fo_acl).  A vnode file answers as the same call on its path does,
 * whether the filesystem supports ACLs or not; descriptors with no vnode
 * return EINVAL, as getvnode_path() did; get and check accept an O_PATH
 * descriptor while set and delete refuse one with EBADF, as before.
 */

#include <sys/param.h>
#include <sys/acl.h>
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

/*
 * __acl_get_fd and __acl_get_file must agree, in result and errno, for
 * both ACL types, because both reach VOP_GETACL on the same vnode.
 */
static void
check_get_oracle(int fd, const char *path)
{
	static const acl_type_t types[] = { ACL_TYPE_ACCESS, ACL_TYPE_NFS4 };
	acl_t ffacl, pacl;
	char *ftext, *ptext;
	int ferr, perr;
	size_t i;

	for (i = 0; i < nitems(types); i++) {
		errno = 0;
		pacl = acl_get_file(path, types[i]);
		perr = errno;
		errno = 0;
		ffacl = acl_get_fd_np(fd, types[i]);
		ferr = errno;
		ATF_CHECK_EQ_MSG(pacl == NULL, ffacl == NULL,
		    "type %d: path %s fd %s", types[i],
		    pacl == NULL ? "fails" : "works",
		    ffacl == NULL ? "fails" : "works");
		if (pacl == NULL || ffacl == NULL) {
			ATF_CHECK_EQ_MSG(perr, ferr, "type %d: errno %d vs %d",
			    types[i], perr, ferr);
		} else {
			ptext = acl_to_text(pacl, NULL);
			ftext = acl_to_text(ffacl, NULL);
			ATF_REQUIRE(ptext != NULL && ftext != NULL);
			ATF_CHECK_STREQ(ptext, ftext);
			acl_free(ptext);
			acl_free(ftext);
		}
		if (pacl != NULL)
			acl_free(pacl);
		if (ffacl != NULL)
			acl_free(ffacl);
	}
}

/* Set and delete through the fd and through the path give the same errno. */
static void
check_set_oracle(int fd, const char *path)
{
	acl_t acl;
	int ferr, perr;

	acl = acl_from_text("u::rw-,g::r--,o::r--");
	ATF_REQUIRE(acl != NULL);
	errno = 0;
	(void)acl_set_file(path, ACL_TYPE_ACCESS, acl);
	perr = errno;
	errno = 0;
	(void)acl_set_fd_np(fd, acl, ACL_TYPE_ACCESS);
	ferr = errno;
	ATF_CHECK_EQ_MSG(perr, ferr, "set: errno %d vs %d", perr, ferr);
	errno = 0;
	(void)acl_delete_def_file(path);
	perr = errno;
	errno = 0;
	(void)acl_delete_fd_np(fd, ACL_TYPE_DEFAULT);
	ferr = errno;
	ATF_CHECK_EQ_MSG(perr, ferr, "delete: errno %d vs %d", perr, ferr);
	errno = 0;
	(void)acl_valid_file_np(path, ACL_TYPE_ACCESS, acl);
	perr = errno;
	errno = 0;
	(void)acl_valid_fd_np(fd, ACL_TYPE_ACCESS, acl);
	ferr = errno;
	ATF_CHECK_EQ_MSG(perr, ferr, "check: errno %d vs %d", perr, ferr);
	acl_free(acl);
}

static void
check_no_vnode(int fd)
{
	acl_t acl;

	acl = acl_from_text("u::rw-,g::r--,o::r--");
	ATF_REQUIRE(acl != NULL);
	errno = 0;
	ATF_CHECK(acl_get_fd_np(fd, ACL_TYPE_ACCESS) == NULL);
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, acl_set_fd_np(fd, acl, ACL_TYPE_ACCESS));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, acl_delete_fd_np(fd, ACL_TYPE_ACCESS));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, acl_valid_fd_np(fd, ACL_TYPE_ACCESS, acl));
	ATF_CHECK_EQ(EINVAL, errno);
	acl_free(acl);
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	check_get_oracle(fd, "file");
	check_set_oracle(fd, "file");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	fd = open("dir", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_get_oracle(fd, "dir");
	check_set_oracle(fd, "dir");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(fifo);
ATF_TC_BODY(fifo, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_get_oracle(fd, "fifo");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_get_oracle(fd, "/dev/null");
	close(fd);
}

/* Get and check work on O_PATH; set and delete are EBADF, as before. */
ATF_TC_WITHOUT_HEAD(opath_file);
ATF_TC_BODY(opath_file, tc)
{
	acl_t acl;
	int fd;

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_get_oracle(fd, "file");
	acl = acl_from_text("u::rw-,g::r--,o::r--");
	ATF_REQUIRE(acl != NULL);
	errno = 0;
	ATF_CHECK_EQ(-1, acl_set_fd_np(fd, acl, ACL_TYPE_ACCESS));
	ATF_CHECK_EQ(EBADF, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, acl_delete_fd_np(fd, ACL_TYPE_ACCESS));
	ATF_CHECK_EQ(EBADF, errno);
	acl_free(acl);
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
	check_get_oracle(fd, "/dev/ptmx");
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
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	errno = 0;
	ATF_CHECK(acl_get_fd_np(fd, ACL_TYPE_ACCESS) == NULL);
	ATF_CHECK_EQ(EBADF, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, fifo);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, opath_file);
	ATF_TP_ADD_TC(tp, pts_master);
	ATF_TP_ADD_TC(tp, no_vnode);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
