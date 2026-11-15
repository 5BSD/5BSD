/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Passing a descriptor over a UNIX domain socket (SCM_RIGHTS) with one
 * byte of data, for requesters and helpers: no ATF call, errno set on
 * failure.  See dq_test.h.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <string.h>

#include "dq_test.h"

int
dqt_send_fd(int sock, int fd)
{
	union {
		struct cmsghdr	 hdr;
		char		 buf[CMSG_SPACE(sizeof(int))];
	} cm;
	struct msghdr mh;
	struct iovec iov;
	char b = 'f';

	memset(&mh, 0, sizeof(mh));
	memset(&cm, 0, sizeof(cm));
	iov.iov_base = &b;
	iov.iov_len = 1;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cm.buf;
	mh.msg_controllen = sizeof(cm.buf);
	cm.hdr.cmsg_len = CMSG_LEN(sizeof(int));
	cm.hdr.cmsg_level = SOL_SOCKET;
	cm.hdr.cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(&cm.hdr), &fd, sizeof(int));
	return (sendmsg(sock, &mh, 0) == 1 ? 0 : -1);
}

int
dqt_recv_fd(int sock)
{
	union {
		struct cmsghdr	 hdr;
		char		 buf[CMSG_SPACE(sizeof(int))];
	} cm;
	struct msghdr mh;
	struct iovec iov;
	char b;
	int fd;

	memset(&mh, 0, sizeof(mh));
	iov.iov_base = &b;
	iov.iov_len = 1;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cm.buf;
	mh.msg_controllen = sizeof(cm.buf);
	if (recvmsg(sock, &mh, 0) != 1)
		return (-1);
	/* One whole SCM_RIGHTS message carrying one descriptor, or none. */
	if ((mh.msg_flags & MSG_CTRUNC) != 0 ||
	    mh.msg_controllen < CMSG_LEN(sizeof(int)) ||
	    cm.hdr.cmsg_level != SOL_SOCKET ||
	    cm.hdr.cmsg_type != SCM_RIGHTS ||
	    cm.hdr.cmsg_len != CMSG_LEN(sizeof(int))) {
		errno = EBADMSG;
		return (-1);
	}
	memcpy(&fd, CMSG_DATA(&cm.hdr), sizeof(int));
	return (fd);
}
