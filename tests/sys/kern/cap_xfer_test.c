/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Tests for cap_xfer_limit(2) and fde_xfer_state enforcement on
 * SCM_RIGHTS file descriptor passing.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#ifndef CAP_XFER_UNLIMITED
#define	CAP_XFER_UNLIMITED	0
#define	CAP_XFER_ONCE		1
#define	CAP_XFER_NONE		2
#endif

/* ---- helpers ---- */

static void
socketpair_stream(int fd[2])
{

	ATF_REQUIRE(socketpair(PF_UNIX, SOCK_STREAM, 0, fd) == 0);
}

static int
sendfd(int sock, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cm;
	char ch = '\0';

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = &ch;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cm) = fd;

	return (sendmsg(sock, &msg, 0) >= 0 ? 0 : errno);
}

static int
recvfd(int sock, int *fdp)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cm;
	char ch;

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = &ch;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(sock, &msg, 0) < 0)
		return (errno);

	cm = CMSG_FIRSTHDR(&msg);
	if (cm == NULL || cm->cmsg_type != SCM_RIGHTS)
		return (EINVAL);

	*fdp = *(int *)CMSG_DATA(cm);
	return (0);
}

/* ---- cap_xfer_limit syscall tests ---- */

ATF_TC_WITHOUT_HEAD(xfer_limit_default);
ATF_TC_BODY(xfer_limit_default, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* Default is UNLIMITED — tightening to ONCE should succeed. */
	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_ONCE) == 0);

	/* Tightening to NONE should succeed. */
	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(xfer_limit_widen_fails);
ATF_TC_BODY(xfer_limit_widen_fails, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);

	/* Widening back to ONCE must fail. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(fd, CAP_XFER_ONCE) == -1);

	/* Widening back to UNLIMITED must fail. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(fd, CAP_XFER_UNLIMITED) == -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(xfer_limit_bad_fd);
ATF_TC_BODY(xfer_limit_bad_fd, tc)
{

	ATF_REQUIRE_ERRNO(EBADF,
	    cap_xfer_limit(999, CAP_XFER_ONCE) == -1);
}

ATF_TC_WITHOUT_HEAD(xfer_limit_bad_state);
ATF_TC_BODY(xfer_limit_bad_state, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE_ERRNO(EINVAL, cap_xfer_limit(fd, -1) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, cap_xfer_limit(fd, 3) == -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(xfer_limit_same_is_ok);
ATF_TC_BODY(xfer_limit_same_is_ok, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_ONCE) == 0);
	/* Setting same value again must succeed. */
	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_ONCE) == 0);

	close(fd);
}

/* ---- dup inheritance tests ---- */

ATF_TC_WITHOUT_HEAD(xfer_limit_dup_inherits);
ATF_TC_BODY(xfer_limit_dup_inherits, tc)
{
	int fd, fd2;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_ONCE) == 0);

	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);

	/* Dup'd descriptor should already be ONCE — can't widen. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(fd2, CAP_XFER_UNLIMITED) == -1);

	/* Can tighten to NONE. */
	ATF_REQUIRE(cap_xfer_limit(fd2, CAP_XFER_NONE) == 0);

	close(fd);
	close(fd2);
}

/* ---- SCM_RIGHTS enforcement tests ---- */

ATF_TC_WITHOUT_HEAD(xfer_unlimited_passes);
ATF_TC_BODY(xfer_unlimited_passes, tc)
{
	int sv[2], fd, recvd;

	socketpair_stream(sv);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* Default UNLIMITED — send should work. */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd) == 0, "sendfd: %s",
	    strerror(errno));
	ATF_REQUIRE(recvfd(sv[1], &recvd) == 0);

	/* Received fd should also be unlimited — can send again. */
	ATF_REQUIRE_MSG(sendfd(sv[0], recvd) == 0, "re-send: %s",
	    strerror(errno));

	close(recvd);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(xfer_none_blocks);
ATF_TC_BODY(xfer_none_blocks, tc)
{
	int sv[2], fd;

	socketpair_stream(sv);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);

	/* Send must fail with ENOTCAPABLE. */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd) == ENOTCAPABLE,
	    "expected ENOTCAPABLE, got %s", strerror(errno));

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(xfer_once_exhausts);
ATF_TC_BODY(xfer_once_exhausts, tc)
{
	int sv[2], fd, recvd;

	socketpair_stream(sv);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_ONCE) == 0);

	/* First send must succeed. */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd) == 0, "sendfd: %s",
	    strerror(errno));
	ATF_REQUIRE(recvfd(sv[1], &recvd) == 0);

	/* Sender's fd is now NONE — second send must fail. */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd) == ENOTCAPABLE,
	    "expected ENOTCAPABLE on re-send, got %s", strerror(errno));

	/* Receiver's fd is also NONE — forwarding must fail. */
	ATF_REQUIRE_MSG(sendfd(sv[0], recvd) == ENOTCAPABLE,
	    "expected ENOTCAPABLE on forward, got %s", strerror(errno));

	close(recvd);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(xfer_orthogonal_to_rights);
ATF_TC_BODY(xfer_orthogonal_to_rights, tc)
{
	int sv[2], fd;
	cap_rights_t rights;

	socketpair_stream(sv);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* Restrict capability rights to read-only. */
	cap_rights_init(&rights, CAP_READ);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);

	/* xfer_state should still be UNLIMITED — send works. */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd) == 0,
	    "cap_rights_limit should not affect transfer: %s",
	    strerror(errno));

	/* Now restrict transfer — cap rights unchanged. */
	close(fd);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);

	/* cap_rights_limit on a XFER_NONE fd should still work. */
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);

	/* But send is blocked by xfer state. */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd) == ENOTCAPABLE,
	    "expected ENOTCAPABLE, got %s", strerror(errno));

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(xfer_fork_inherits);
ATF_TC_BODY(xfer_fork_inherits, tc)
{
	int fd, status;
	pid_t pid;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Child: fd should have inherited NONE — widen must fail. */
		_exit(cap_xfer_limit(fd, CAP_XFER_UNLIMITED) == -1 &&
		    errno == ENOTCAPABLE ? 0 : 1);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child saw wrong xfer state after fork");

	close(fd);
}

ATF_TC_WITHOUT_HEAD(xfer_close_reopen_resets);
ATF_TC_BODY(xfer_close_reopen_resets, tc)
{
	int fd, fd2;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);
	close(fd);

	/* Reopen — should get a fresh descriptor with UNLIMITED. */
	fd2 = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd2 >= 0);

	/* Must be able to set ONCE (proves it's UNLIMITED, not stale NONE). */
	ATF_REQUIRE(cap_xfer_limit(fd2, CAP_XFER_ONCE) == 0);

	close(fd2);
}

ATF_TC_WITHOUT_HEAD(xfer_multi_fd_atomic);
ATF_TC_BODY(xfer_multi_fd_atomic, tc)
{
	int sv[2], fd1, fd2;
	struct msghdr msg;
	struct iovec iov;
	char buf[CMSG_SPACE(2 * sizeof(int))];
	struct cmsghdr *cm;
	int *fdp;
	char ch = '\0';

	socketpair_stream(sv);
	fd1 = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd1 >= 0);
	fd2 = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd2 >= 0);

	/* fd1 is UNLIMITED, fd2 is NONE. */
	ATF_REQUIRE(cap_xfer_limit(fd2, CAP_XFER_NONE) == 0);

	/* Try to send both in one sendmsg — should fail atomically. */
	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));
	iov.iov_base = &ch;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_len = CMSG_LEN(2 * sizeof(int));
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	fdp = (int *)CMSG_DATA(cm);
	fdp[0] = fd1;
	fdp[1] = fd2;

	ATF_REQUIRE_MSG(sendmsg(sv[0], &msg, 0) == -1 &&
	    errno == ENOTCAPABLE,
	    "multi-fd send with NONE fd should fail: %s", strerror(errno));

	close(fd1);
	close(fd2);
	close(sv[0]);
	close(sv[1]);
}

/* ---- SCM_RIGHTS enforcement: send-side consumption ---- */

ATF_TC_WITHOUT_HEAD(xfer_once_consumed_on_send);
ATF_TC_BODY(xfer_once_consumed_on_send, tc)
{
	int sv[2], fd;

	socketpair_stream(sv);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_ONCE) == 0);

	/* First send succeeds — state consumed on send side. */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd) == 0, "sendfd: %s",
	    strerror(errno));

	/*
	 * Second send must fail BEFORE the receiver calls recvmsg.
	 * This proves consumption happens at send time.
	 */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd) == ENOTCAPABLE,
	    "expected ENOTCAPABLE, got %s", strerror(errno));

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

/* ---- SCM_RIGHTS enforcement: received fd state ---- */

ATF_TC_WITHOUT_HEAD(xfer_recv_unlimited_preserved);
ATF_TC_BODY(xfer_recv_unlimited_preserved, tc)
{
	int sv[2], fd, recvd;

	socketpair_stream(sv);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* Default UNLIMITED — send and receive. */
	ATF_REQUIRE(sendfd(sv[0], fd) == 0);
	ATF_REQUIRE(recvfd(sv[1], &recvd) == 0);

	/* Received fd should be UNLIMITED — can tighten to ONCE. */
	ATF_REQUIRE(cap_xfer_limit(recvd, CAP_XFER_ONCE) == 0);
	/* And that should succeed, proving it was UNLIMITED. */

	close(recvd);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(xfer_recv_once_arrives_none);
ATF_TC_BODY(xfer_recv_once_arrives_none, tc)
{
	int sv[2], fd, recvd;

	socketpair_stream(sv);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_ONCE) == 0);

	/* Send consumes ONCE → receiver gets NONE. */
	ATF_REQUIRE(sendfd(sv[0], fd) == 0);
	ATF_REQUIRE(recvfd(sv[1], &recvd) == 0);

	/* Received fd should be NONE — cannot widen. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(recvd, CAP_XFER_UNLIMITED) == -1);
	/* Setting same NONE is ok. */
	ATF_REQUIRE(cap_xfer_limit(recvd, CAP_XFER_NONE) == 0);

	/* Cannot forward via SCM_RIGHTS. */
	ATF_REQUIRE_MSG(sendfd(sv[0], recvd) == ENOTCAPABLE,
	    "forwarding NONE fd should fail: %s", strerror(errno));

	close(recvd);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

/* ---- SCM_RIGHTS enforcement: multi-fd atomicity for ONCE ---- */

ATF_TC_WITHOUT_HEAD(xfer_multi_once_not_consumed);
ATF_TC_BODY(xfer_multi_once_not_consumed, tc)
{
	int sv[2], fd_once, fd_none;
	struct msghdr msg;
	struct iovec iov;
	char buf[CMSG_SPACE(2 * sizeof(int))];
	struct cmsghdr *cm;
	int *fdp;
	char ch = '\0';

	socketpair_stream(sv);
	fd_once = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd_once >= 0);
	fd_none = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd_none >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd_once, CAP_XFER_ONCE) == 0);
	ATF_REQUIRE(cap_xfer_limit(fd_none, CAP_XFER_NONE) == 0);

	/* Multi-fd send: fd_none causes rejection. */
	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));
	iov.iov_base = &ch;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_len = CMSG_LEN(2 * sizeof(int));
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	fdp = (int *)CMSG_DATA(cm);
	fdp[0] = fd_once;
	fdp[1] = fd_none;

	ATF_REQUIRE_MSG(sendmsg(sv[0], &msg, 0) == -1 &&
	    errno == ENOTCAPABLE,
	    "multi-fd send should fail: %s", strerror(errno));

	/*
	 * fd_once should still be ONCE — the NONE fd caused early
	 * rejection before any state was consumed.  Verify by
	 * sending fd_once alone (should succeed).
	 */
	ATF_REQUIRE_MSG(sendfd(sv[0], fd_once) == 0,
	    "ONCE fd should not have been consumed: %s", strerror(errno));

	close(fd_once);
	close(fd_none);
	close(sv[0]);
	close(sv[1]);
}

/* ---- capability mode ---- */

ATF_TC_WITHOUT_HEAD(xfer_capmode);
ATF_TC_BODY(xfer_capmode, tc)
{
	int fd, status;
	pid_t pid;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (cap_enter() != 0)
			_exit(10);
		/* cap_xfer_limit must work in capability mode. */
		if (cap_xfer_limit(fd, CAP_XFER_ONCE) != 0)
			_exit(1);
		if (cap_xfer_limit(fd, CAP_XFER_NONE) != 0)
			_exit(2);
		/* Widening must still fail. */
		if (cap_xfer_limit(fd, CAP_XFER_ONCE) == 0)
			_exit(3);
		if (errno != ENOTCAPABLE)
			_exit(4);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "cap mode test failed: exit %d",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(xfer_caps_attenuate_scm_rights);
ATF_TC_BODY(xfer_caps_attenuate_scm_rights, tc)
{
	cap_ioctl_t cmds[2], gotcmd;
	cap_rights_t limit, wider, received;
	uint32_t fcntls;
	int fd, fd2, passfd, recvd, sv[2];

	socketpair_stream(sv);
	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);

	cap_rights_init(&limit, CAP_READ, CAP_IOCTL, CAP_FCNTL);
	ATF_REQUIRE(cap_xfer_rights_limit(fd, &limit) == 0);
	cmds[0] = FIONREAD;
	ATF_REQUIRE(cap_xfer_ioctls_limit(fd, cmds, 1) == 0);
	ATF_REQUIRE(cap_xfer_fcntls_limit(fd, CAP_FCNTL_GETFL) == 0);

	/* Every ceiling is monotonic. */
	cap_rights_init(&wider, CAP_READ, CAP_WRITE, CAP_IOCTL, CAP_FCNTL);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_rights_limit(fd, &wider) == -1);
	cmds[1] = FIONBIO;
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_ioctls_limit(fd, cmds, 2) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_fcntls_limit(fd, CAP_FCNTL_ALL) == -1);

	/* dup() carries the ceiling, while the sender retains broad rights. */
	passfd = dup(fd);
	ATF_REQUIRE(passfd >= 0);
	ATF_REQUIRE(sendfd(sv[0], passfd) == 0);
	ATF_REQUIRE(recvfd(sv[1], &recvd) == 0);

	ATF_REQUIRE(cap_rights_get(fd, &received) == 0);
	ATF_REQUIRE(cap_rights_is_set(&received, CAP_WRITE));

	ATF_REQUIRE(cap_rights_get(recvd, &received) == 0);
	ATF_REQUIRE(cap_rights_is_set(&received, CAP_READ));
	ATF_REQUIRE(!cap_rights_is_set(&received, CAP_WRITE));
	ATF_REQUIRE(cap_rights_is_set(&received, CAP_IOCTL));
	ATF_REQUIRE(cap_rights_is_set(&received, CAP_FCNTL));

	ATF_REQUIRE(cap_ioctls_get(recvd, &gotcmd, 1) == 1);
	ATF_REQUIRE(gotcmd == FIONREAD);
	ATF_REQUIRE(cap_fcntls_get(recvd, &fcntls) == 0);
	ATF_REQUIRE(fcntls == CAP_FCNTL_GETFL);
	close(recvd);

	/*
	 * Current rights are also a hard upper bound: a ceiling that contains
	 * WRITE cannot restore WRITE after the sender has removed it.
	 */
	fd2 = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd2 >= 0);
	cap_rights_init(&wider, CAP_READ, CAP_WRITE);
	ATF_REQUIRE(cap_xfer_rights_limit(fd2, &wider) == 0);
	cap_rights_init(&limit, CAP_READ);
	ATF_REQUIRE(cap_rights_limit(fd2, &limit) == 0);
	ATF_REQUIRE(sendfd(sv[0], fd2) == 0);
	ATF_REQUIRE(recvfd(sv[1], &recvd) == 0);
	ATF_REQUIRE(cap_rights_get(recvd, &received) == 0);
	ATF_REQUIRE(cap_rights_is_set(&received, CAP_READ));
	ATF_REQUIRE(!cap_rights_is_set(&received, CAP_WRITE));

	close(recvd);
	close(fd2);
	close(passfd);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

/* ---- test registration ---- */

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, xfer_limit_default);
	ATF_TP_ADD_TC(tp, xfer_limit_widen_fails);
	ATF_TP_ADD_TC(tp, xfer_limit_bad_fd);
	ATF_TP_ADD_TC(tp, xfer_limit_bad_state);
	ATF_TP_ADD_TC(tp, xfer_limit_same_is_ok);
	ATF_TP_ADD_TC(tp, xfer_limit_dup_inherits);
	ATF_TP_ADD_TC(tp, xfer_unlimited_passes);
	ATF_TP_ADD_TC(tp, xfer_none_blocks);
	ATF_TP_ADD_TC(tp, xfer_once_exhausts);
	ATF_TP_ADD_TC(tp, xfer_orthogonal_to_rights);
	ATF_TP_ADD_TC(tp, xfer_fork_inherits);
	ATF_TP_ADD_TC(tp, xfer_close_reopen_resets);
	ATF_TP_ADD_TC(tp, xfer_multi_fd_atomic);

	/* SCM_RIGHTS enforcement */
	ATF_TP_ADD_TC(tp, xfer_once_consumed_on_send);
	ATF_TP_ADD_TC(tp, xfer_recv_unlimited_preserved);
	ATF_TP_ADD_TC(tp, xfer_recv_once_arrives_none);
	ATF_TP_ADD_TC(tp, xfer_multi_once_not_consumed);

	/* capability mode */
	ATF_TP_ADD_TC(tp, xfer_capmode);
	ATF_TP_ADD_TC(tp, xfer_caps_attenuate_scm_rights);

	return (atf_no_error());
}
