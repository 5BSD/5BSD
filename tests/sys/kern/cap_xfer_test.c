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
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
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

/* ---- what an installed descriptor looks like, kind by kind ---- */

/*
 * For each kind of descriptor: what F_GETFD and F_GETFL say right after
 * it is made, whether dup(2) works and what the copy's flags are,
 * whether a fork(2) child and a program it then execs still have the
 * number, whether SCM_RIGHTS accepts it and what flags the received
 * copy has, and whether the parent can take it with pddupfd(2) and what
 * flags that copy has.
 *
 * The supervisor-control series adds a way to install descriptors into
 * a process; this table is what every existing way of getting one
 * produces today, so that a change to the shared install paths shows.
 * The numbers were recorded by running the case on the kernel before
 * the series.
 */
enum is_kind {
	IS_REGULAR,
	IS_PIPE,
	IS_SOCKET,
	IS_KQUEUE,
	IS_DEVNULL,
	IS_PROCDESC,
	IS_XFER_NONE,		/* regular file, cap_xfer_limit NONE */
	IS_CLOEXEC_LOCKED,	/* regular file, cap_cloexec_limit LOCKED */
	IS_RESTRICTED,		/* both, and cap_clofork_limit LOCKED */
	IS_NKINDS
};

/* -1 in a row means "not applicable": the step before it failed. */
struct is_row {
	int	fd;		/* the subject's number for it */
	int	getfd;		/* F_GETFD */
	int	getfl;		/* F_GETFL */
	int	dup_errno;	/* dup(2): 0 or errno */
	int	dup_getfd;	/* F_GETFD of the dup */
	int	fork_errno;	/* fstat(2) in a fork(2) child: 0 or errno */
	int	exec_status;	/* sh -c ': <&fd' after fork: 0 has it, 2 not */
	int	scm_errno;	/* sendmsg(SCM_RIGHTS): 0 or errno */
	int	scm_getfd;	/* F_GETFD of the received copy */
	int	pddup_errno;	/* the parent's pddupfd(2): 0 or errno */
	int	pddup_getfd;	/* F_GETFD of the parent's copy */
};

static const struct {
	const char	*name;
	struct is_row	want;
} is_table[IS_NKINDS] = {
	[IS_REGULAR] = { "regular file",
	    { 0, 0, O_RDWR, 0, 0, 0, 0, 0, 0, 0, FD_CLOEXEC } },
	[IS_PIPE] = { "pipe",
	    { 0, 0, O_RDWR, 0, 0, 0, 0, 0, 0, 0, FD_CLOEXEC } },
	[IS_SOCKET] = { "socket",
	    { 0, 0, O_RDWR, 0, 0, 0, 0, 0, 0, 0, FD_CLOEXEC } },
	[IS_KQUEUE] = { "kqueue",
	    { 0, 0, O_RDWR, 0, 0, EBADF, 2, EOPNOTSUPP, -1, EOPNOTSUPP,
	    -1 } },
	[IS_DEVNULL] = { "/dev/null",
	    { 0, 0, O_RDWR, 0, 0, 0, 0, 0, 0, 0, FD_CLOEXEC } },
	[IS_PROCDESC] = { "process descriptor",
	    { 0, 0, O_RDWR, 0, 0, 0, 0, 0, 0, 0, FD_CLOEXEC } },
	[IS_XFER_NONE] = { "regular file, transfer NONE",
	    { 0, 0, O_RDWR, 0, 0, 0, 0, ENOTCAPABLE, -1, ENOTCAPABLE,
	    -1 } },
	[IS_CLOEXEC_LOCKED] = { "regular file, close-on-exec LOCKED",
	    { 0, 0, O_RDWR, 0, 0, 0, 2, 0, 0, 0, FD_CLOEXEC } },
	[IS_RESTRICTED] = { "regular file, NONE and both LOCKED",
	    { 0, 0, O_RDWR, 0, 0, EBADF, 2, ENOTCAPABLE, -1, ENOTCAPABLE,
	    -1 } },
};

/* Runs in the subject process: no ATF calls.  Returns the fd or -1. */
static int
is_make(enum is_kind kind)
{
	int fd, pd, pfd[2];

	switch (kind) {
	case IS_REGULAR:
	case IS_XFER_NONE:
	case IS_CLOEXEC_LOCKED:
	case IS_RESTRICTED:
		fd = open("install_states.file", O_RDWR | O_CREAT, 0600);
		if (fd == -1)
			return (-1);
		if ((kind == IS_XFER_NONE || kind == IS_RESTRICTED) &&
		    cap_xfer_limit(fd, CAP_XFER_NONE) != 0)
			return (-1);
		if ((kind == IS_CLOEXEC_LOCKED || kind == IS_RESTRICTED) &&
		    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) != 0)
			return (-1);
		if (kind == IS_RESTRICTED &&
		    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) != 0)
			return (-1);
		return (fd);
	case IS_PIPE:
		if (pipe(pfd) != 0)
			return (-1);
		return (pfd[0]);
	case IS_SOCKET:
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, pfd) != 0)
			return (-1);
		return (pfd[0]);
	case IS_KQUEUE:
		return (kqueue());
	case IS_DEVNULL:
		return (open("/dev/null", O_RDWR));
	case IS_PROCDESC:
		switch (pdfork(&pd, 0)) {
		case -1:
			return (-1);
		case 0:
			for (;;)
				pause();
		}
		return (pd);
	default:
		return (-1);
	}
}

/* Run fn-less probes in a fork(2) child; returns its exit status. */
static int
is_fork_probe(int fd, bool exec)
{
	struct stat sb;
	char cmd[32];
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return (-1);
	if (pid == 0) {
		if (!exec)
			_exit(fstat(fd, &sb) == 0 ? 0 : errno);
		snprintf(cmd, sizeof(cmd), ": <&%d", fd);
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static void
is_subject(enum is_kind kind, int rep, int cmd)
{
	struct is_row row;
	int d, fd, sp[2];
	char c;

	memset(&row, 0xff, sizeof(row));
	fd = is_make(kind);
	row.fd = fd;
	/* sh(1) takes a single digit in "<&n". */
	if (fd == -1 || fd > 9)
		goto out;
	row.getfd = fcntl(fd, F_GETFD);
	row.getfl = fcntl(fd, F_GETFL);
	d = dup(fd);
	row.dup_errno = d == -1 ? errno : 0;
	if (d != -1) {
		row.dup_getfd = fcntl(d, F_GETFD);
		close(d);
	}
	row.fork_errno = is_fork_probe(fd, false);
	row.exec_status = is_fork_probe(fd, true);
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sp) != 0) {
		row.fd = -1;
		goto out;
	}
	row.scm_errno = sendfd(sp[0], fd);
	if (row.scm_errno == 0 && recvfd(sp[1], &d) == 0) {
		row.scm_getfd = fcntl(d, F_GETFD);
		close(d);
	}
	close(sp[0]);
	close(sp[1]);
out:
	if (write(rep, &row, sizeof(row)) != sizeof(row))
		_exit(1);
	/* Hold the descriptor until the parent has tried pddupfd(2). */
	(void)read(cmd, &c, 1);
	_exit(0);
}

#define	IS_CHECK(field)							\
	ATF_CHECK_EQ_MSG(want->field, row.field,			\
	    "%s: " #field " is %d (%#x), expected %d (%#x)", name,	\
	    row.field, row.field, want->field, want->field)

ATF_TC_WITHOUT_HEAD(install_states_unchanged);
ATF_TC_BODY(install_states_unchanged, tc)
{
	const struct is_row *want;
	struct is_row row;
	const char *name;
	pid_t pid;
	int cmd[2], copy, kind, pd, rep[2], status;
	char c;

	for (kind = 0; kind < IS_NKINDS; kind++) {
		name = is_table[kind].name;
		want = &is_table[kind].want;

		ATF_REQUIRE_EQ(0, pipe(rep));
		ATF_REQUIRE_EQ(0, pipe(cmd));
		pid = pdfork(&pd, 0);
		ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
		if (pid == 0) {
			/* Keep the numbers low and the same for every kind. */
			if (dup2(rep[1], 3) == -1 || dup2(cmd[0], 4) == -1)
				_exit(1);
			closefrom(5);
			is_subject(kind, 3, 4);
		}
		close(rep[1]);
		close(cmd[0]);
		ATF_REQUIRE_EQ_MSG(sizeof(row), (size_t)read(rep[0], &row,
		    sizeof(row)), "%s: no report", name);
		ATF_REQUIRE_MSG(row.fd >= 0 && row.fd <= 9,
		    "%s: could not be made (fd %d)", name, row.fd);

		errno = 0;
		copy = pddupfd(pd, row.fd, 0);
		row.pddup_errno = copy == -1 ? errno : 0;
		row.pddup_getfd = -1;
		if (copy != -1) {
			row.pddup_getfd = fcntl(copy, F_GETFD);
			ATF_REQUIRE_EQ(0, close(copy));
		}

		c = 'x';
		ATF_REQUIRE_EQ(1, write(cmd[1], &c, 1));
		ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
		ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "%s: subject status %#x", name, status);
		close(pd);
		close(rep[0]);
		close(cmd[1]);

		printf("%s: fd %d getfd %#x getfl %#x dup %d/%#x fork %d "
		    "exec %d scm %d/%#x pddupfd %d/%#x\n", name, row.fd,
		    row.getfd, row.getfl, row.dup_errno, row.dup_getfd,
		    row.fork_errno, row.exec_status, row.scm_errno,
		    row.scm_getfd, row.pddup_errno, row.pddup_getfd);
		IS_CHECK(getfd);
		IS_CHECK(getfl);
		IS_CHECK(dup_errno);
		IS_CHECK(dup_getfd);
		IS_CHECK(fork_errno);
		IS_CHECK(exec_status);
		IS_CHECK(scm_errno);
		IS_CHECK(scm_getfd);
		IS_CHECK(pddup_errno);
		IS_CHECK(pddup_getfd);
	}
}

/*
 * ---- pddupfd(2) as a descriptor transfer: refusals, their order, and
 * what a copy consumes and carries ----
 *
 * The subject holds one descriptor per rule at a fixed number; the parent
 * copies each through the subject's process descriptor.
 */
#define	PD_FILE		10	/* /dev/null, nothing limited */
#define	PD_KQUEUE	11	/* not passable */
#define	PD_NONE		12	/* CAP_XFER_NONE */
#define	PD_KQ_NONE	13	/* not passable and CAP_XFER_NONE */
#define	PD_ONCE		14	/* CAP_XFER_ONCE */
#define	PD_ONCE_FULL	15	/* CAP_XFER_ONCE, copied into a full table */
#define	PD_CEILING	16	/* rights READ|WRITE|FSTAT, ceiling READ|FSTAT */
#define	PD_LOCKED	17	/* close-on-exec and close-on-fork locked */
#define	PD_CLOSED	30	/* not open */

static void
pd_subject(int rep, int cmd)
{
	cap_rights_t rights;
	int fd, ok;
	char c;

	ok = 1;
#define	PD_AT(n, expr) do {						\
	fd = (expr);							\
	if (fd == -1 || dup2(fd, (n)) == -1)				\
		ok = 0;							\
	else if (fd != (n))						\
		(void)close(fd);					\
} while (0)
	PD_AT(PD_FILE, open("/dev/null", O_RDWR));
	PD_AT(PD_KQUEUE, kqueue());
	PD_AT(PD_NONE, open("/dev/null", O_RDWR));
	ok &= cap_xfer_limit(PD_NONE, CAP_XFER_NONE) == 0;
	PD_AT(PD_KQ_NONE, kqueue());
	ok &= cap_xfer_limit(PD_KQ_NONE, CAP_XFER_NONE) == 0;
	PD_AT(PD_ONCE, open("/dev/null", O_RDWR));
	ok &= cap_xfer_limit(PD_ONCE, CAP_XFER_ONCE) == 0;
	PD_AT(PD_ONCE_FULL, open("/dev/null", O_RDWR));
	ok &= cap_xfer_limit(PD_ONCE_FULL, CAP_XFER_ONCE) == 0;
	PD_AT(PD_CEILING, open("/dev/null", O_RDWR));
	ok &= cap_rights_limit(PD_CEILING, cap_rights_init(&rights, CAP_READ,
	    CAP_WRITE, CAP_FSTAT)) == 0;
	ok &= cap_xfer_rights_limit(PD_CEILING, cap_rights_init(&rights,
	    CAP_READ, CAP_FSTAT)) == 0;
	PD_AT(PD_LOCKED, open("/dev/null", O_RDWR));
	ok &= cap_cloexec_limit(PD_LOCKED, CAP_CLOEXEC_LOCKED) == 0;
	ok &= cap_clofork_limit(PD_LOCKED, CAP_CLOFORK_LOCKED) == 0;
#undef PD_AT
	c = ok ? 'y' : 'n';
	if (write(rep, &c, 1) != 1)
		_exit(1);
	(void)read(cmd, &c, 1);
	_exit(0);
}

ATF_TC_WITHOUT_HEAD(pddupfd_transfer_rules);
ATF_TC_BODY(pddupfd_transfer_rules, tc)
{
	cap_rights_t got, want;
	struct rlimit rl, save;
	pid_t pid;
	int cmd[2], copy, fill[64], i, nfill, pd, rep[2], status, sv[2];
	char c;

	ATF_REQUIRE_EQ(0, pipe(rep));
	ATF_REQUIRE_EQ(0, pipe(cmd));
	pid = pdfork(&pd, 0);
	ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		if (dup2(rep[1], 3) == -1 || dup2(cmd[0], 4) == -1)
			_exit(1);
		closefrom(5);
		pd_subject(3, 4);
	}
	close(rep[1]);
	close(cmd[0]);
	ATF_REQUIRE_EQ(1, read(rep[0], &c, 1));
	ATF_REQUIRE_MSG(c == 'y', "the subject could not set up");

	/* The refusals, and the order of the two that one entry can meet. */
	ATF_CHECK_ERRNO(EBADF, pddupfd(pd, PD_CLOSED, 0) == -1);
	ATF_CHECK_ERRNO(EOPNOTSUPP, pddupfd(pd, PD_KQUEUE, 0) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE, pddupfd(pd, PD_NONE, 0) == -1);
	ATF_CHECK_ERRNO(EOPNOTSUPP, pddupfd(pd, PD_KQ_NONE, 0) == -1);

	/* An unlimited source: the copy may be sent on. */
	socketpair_stream(sv);
	copy = pddupfd(pd, PD_FILE, 0);
	ATF_REQUIRE_MSG(copy != -1, "pddupfd: %s", strerror(errno));
	ATF_CHECK_EQ(0, sendfd(sv[0], copy));
	ATF_REQUIRE_EQ(0, close(copy));

	/* A transfer-once source: one copy, itself CAP_XFER_NONE. */
	copy = pddupfd(pd, PD_ONCE, 0);
	ATF_REQUIRE_MSG(copy != -1, "pddupfd of a ONCE entry: %s",
	    strerror(errno));
	ATF_CHECK_EQ(ENOTCAPABLE, sendfd(sv[0], copy));
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(copy, CAP_XFER_UNLIMITED) == -1);
	ATF_REQUIRE_EQ(0, close(copy));
	ATF_CHECK_ERRNO(ENOTCAPABLE, pddupfd(pd, PD_ONCE, 0) == -1);

	/*
	 * No free number in the caller: EMFILE, after the source was
	 * consumed, as when an SCM_RIGHTS receiver cannot allocate.
	 */
	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &save));
	rl = save;
	rl.rlim_cur = 48;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &rl));
	for (nfill = 0; nfill < (int)nitems(fill); nfill++) {
		fill[nfill] = dup(sv[0]);
		if (fill[nfill] == -1)
			break;
	}
	ATF_CHECK_ERRNO(EMFILE, pddupfd(pd, PD_ONCE_FULL, 0) == -1);
	for (i = 0; i < nfill; i++)
		(void)close(fill[i]);
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &save));
	ATF_CHECK_ERRNO(ENOTCAPABLE, pddupfd(pd, PD_ONCE_FULL, 0) == -1);

	/* The copy's rights are the source's under its transfer ceiling. */
	copy = pddupfd(pd, PD_CEILING, 0);
	ATF_REQUIRE_MSG(copy != -1, "pddupfd: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, cap_rights_get(copy, &got));
	cap_rights_init(&want, CAP_READ, CAP_FSTAT);
	ATF_CHECK(cap_rights_contains(&want, &got) &&
	    cap_rights_contains(&got, &want));
	ATF_REQUIRE_EQ(0, close(copy));

	/* The two propagation locks carry: the copy cannot loosen them. */
	copy = pddupfd(pd, PD_LOCKED, 0);
	ATF_REQUIRE_MSG(copy != -1, "pddupfd: %s", strerror(errno));
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(copy, CAP_CLOEXEC_UNLOCKED) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(copy, CAP_CLOFORK_UNLOCKED) == -1);
	ATF_REQUIRE_EQ(0, close(copy));
	/* A copy of an unlocked source has neither lock. */
	copy = pddupfd(pd, PD_FILE, 0);
	ATF_REQUIRE_MSG(copy != -1, "pddupfd: %s", strerror(errno));
	ATF_CHECK_EQ(0, cap_cloexec_limit(copy, CAP_CLOEXEC_UNLOCKED));
	ATF_CHECK_EQ(0, cap_clofork_limit(copy, CAP_CLOFORK_UNLOCKED));
	ATF_REQUIRE_EQ(0, close(copy));

	c = 'x';
	ATF_REQUIRE_EQ(1, write(cmd[1], &c, 1));
	ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(pd);
	close(rep[0]);
	close(cmd[1]);
	close(sv[0]);
	close(sv[1]);
}

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
	ATF_TP_ADD_TC(tp, install_states_unchanged);
	ATF_TP_ADD_TC(tp, pddupfd_transfer_rules);

	return (atf_no_error());
}
