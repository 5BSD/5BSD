/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Tests for capability-pure syscalls (SYF_CAPREQUIRED) and the
 * per-descriptor noambient limiter (cap_ambient_limit).
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/procctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/procdesc.h>
#include <sys/filio.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <aio.h>

#ifndef SYS_cap_fchmod
#define	SYS_cap_fchmod		606
#endif
#ifndef SYS_cap_ftruncate
#define	SYS_cap_ftruncate	628
#endif
#ifndef SYS_cap_ioctl
#define	SYS_cap_ioctl		625
#endif
#ifndef SYS_cap_mmap
#define	SYS_cap_mmap		626
#endif
#ifndef SYS_cap_sendmsg
#define	SYS_cap_sendmsg		622
#endif
#ifndef SYS_cap_recvmsg
#define	SYS_cap_recvmsg		623
#endif
#ifndef SYS_cap_ambient_limit
#define	SYS_cap_ambient_limit	629
#endif

/*
 * Helper: run test body in a forked child so cap_enter() doesn't
 * affect the test runner.
 */
static int
in_child(void (*fn)(int *), int *statusp)
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int result = 0;
		fn(&result);
		_exit(result);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	if (statusp != NULL)
		*statusp = status;
	return (WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

/* ---- CAPREQUIRED gate tests ---- */

static void
cap_fchmod_outside_capmode_body(int *result)
{
	int fd;

	fd = open("/tmp/cap_pure_test_file", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }

	/* cap_fchmod outside cap mode should fail with ENOTCAPABLE */
	if (syscall(SYS_cap_fchmod, fd, 0600) == 0) { *result = 2; return; }
	if (errno != ENOTCAPABLE) { *result = 3; return; }

	close(fd);
	unlink("/tmp/cap_pure_test_file");
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_fchmod_outside_capmode);
ATF_TC_BODY(cap_fchmod_outside_capmode, tc)
{
	int r;

	r = in_child(cap_fchmod_outside_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_fchmod outside cap mode: expected ENOTCAPABLE (result=%d)", r);
}

static void
cap_fchmod_inside_capmode_body(int *result)
{
	struct stat sb;
	int fd;

	fd = open("/tmp/cap_pure_test_file2", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }

	if (cap_enter() != 0) { *result = 2; return; }

	/* cap_fchmod inside cap mode should succeed */
	if (syscall(SYS_cap_fchmod, fd, 0600) != 0) { *result = 3; return; }

	/* Verify the mode actually changed */
	if (fstat(fd, &sb) != 0) { *result = 4; return; }
	if ((sb.st_mode & 0777) != 0600) { *result = 5; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_fchmod_inside_capmode);
ATF_TC_BODY(cap_fchmod_inside_capmode, tc)
{
	int r;

	r = in_child(cap_fchmod_inside_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_fchmod inside cap mode: expected success (result=%d)", r);
	unlink("/tmp/cap_pure_test_file2");
}

/* ---- Ambient fchmod unchanged ---- */

static void
ambient_fchmod_unchanged_body(int *result)
{
	struct stat sb;
	int fd;

	fd = open("/tmp/cap_pure_test_file3", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }

	/* Ambient fchmod should still work outside cap mode */
	if (fchmod(fd, 0600) != 0) { *result = 2; return; }
	if (fstat(fd, &sb) != 0) { *result = 3; return; }
	if ((sb.st_mode & 0777) != 0600) { *result = 4; return; }

	/* Ambient fchmod should still work inside cap mode */
	if (cap_enter() != 0) { *result = 5; return; }
	if (fchmod(fd, 0644) != 0) { *result = 6; return; }
	if (fstat(fd, &sb) != 0) { *result = 7; return; }
	if ((sb.st_mode & 0777) != 0644) { *result = 8; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(ambient_fchmod_unchanged);
ATF_TC_BODY(ambient_fchmod_unchanged, tc)
{
	int r;

	r = in_child(ambient_fchmod_unchanged_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "ambient fchmod behavior changed (result=%d)", r);
	unlink("/tmp/cap_pure_test_file3");
}

/* ---- cap_fchmod on non-vnode fd ---- */

static void
cap_fchmod_nonvnode_body(int *result)
{
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}

	if (cap_enter() != 0) { *result = 2; return; }

	/* cap_fchmod on socket should fail (vnode-only) */
	if (syscall(SYS_cap_fchmod, sv[0], 0600) == 0) { *result = 3; return; }
	/* getvnode returns EINVAL for non-vnodes */
	if (errno != EINVAL) { *result = 4; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_fchmod_nonvnode);
ATF_TC_BODY(cap_fchmod_nonvnode, tc)
{
	int r;

	r = in_child(cap_fchmod_nonvnode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_fchmod on socket: expected EINVAL (result=%d)", r);
}

/* ---- Capsicum rights still enforced on cap_* ---- */

static void
cap_fchmod_rights_body(int *result)
{
	cap_rights_t rights;
	int fd;

	fd = open("/tmp/cap_pure_test_file4", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }

	/* Remove CAP_FCHMOD right */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	if (cap_rights_limit(fd, &rights) != 0) { *result = 2; return; }

	if (cap_enter() != 0) { *result = 3; return; }

	/* cap_fchmod without CAP_FCHMOD right should fail */
	if (syscall(SYS_cap_fchmod, fd, 0600) == 0) { *result = 4; return; }
	if (errno != ENOTCAPABLE) { *result = 5; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_fchmod_rights);
ATF_TC_BODY(cap_fchmod_rights, tc)
{
	int r;

	r = in_child(cap_fchmod_rights_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_fchmod without CAP_FCHMOD: expected ENOTCAPABLE (result=%d)",
	    r);
	unlink("/tmp/cap_pure_test_file4");
}

/* ---- cap_ambient_limit tests ---- */

static void
ambient_limit_outside_capmode_body(int *result)
{
	char buf[16];
	int fd;

	fd = open("/tmp/cap_pure_test_file5", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }
	if (write(fd, "hello", 5) != 5) { *result = 2; return; }
	if (lseek(fd, 0, SEEK_SET) != 0) { *result = 3; return; }

	/* Set noambient outside cap mode */
	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 4; return; }

	/* Outside cap mode, read should still work (marker is inert) */
	if (read(fd, buf, 5) != 5) { *result = 5; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(ambient_limit_outside_capmode);
ATF_TC_BODY(ambient_limit_outside_capmode, tc)
{
	int r;

	r = in_child(ambient_limit_outside_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "noambient marker should be inert outside cap mode (result=%d)", r);
	unlink("/tmp/cap_pure_test_file5");
}

static void
ambient_limit_inside_capmode_body(int *result)
{
	char buf[16];
	int fd;

	fd = open("/tmp/cap_pure_test_file6", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }
	if (write(fd, "hello", 5) != 5) { *result = 2; return; }
	if (lseek(fd, 0, SEEK_SET) != 0) { *result = 3; return; }

	/* Set noambient then enter cap mode */
	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 4; return; }
	if (cap_enter() != 0) { *result = 5; return; }

	/* read should succeed (MAC skipped in cap mode with noambient) */
	if (read(fd, buf, 5) != 5) { *result = 6; return; }
	if (memcmp(buf, "hello", 5) != 0) { *result = 7; return; }

	/* write should succeed too */
	if (lseek(fd, 0, SEEK_SET) != 0) { *result = 8; return; }
	if (write(fd, "world", 5) != 5) { *result = 9; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(ambient_limit_inside_capmode);
ATF_TC_BODY(ambient_limit_inside_capmode, tc)
{
	int r;

	r = in_child(ambient_limit_inside_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "noambient read/write in cap mode (result=%d)", r);
	unlink("/tmp/cap_pure_test_file6");
}

/* ---- cap_ambient_limit invalid fd ---- */

ATF_TC_WITHOUT_HEAD(ambient_limit_bad_fd);
ATF_TC_BODY(ambient_limit_bad_fd, tc)
{
	ATF_REQUIRE(syscall(SYS_cap_ambient_limit, 999) == -1);
	ATF_REQUIRE(errno == EBADF);
}

/* ---- cap_ambient_limit monotonic ---- */

static void
ambient_limit_monotonic_body(int *result)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) { *result = 1; return; }

	/* First call succeeds */
	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 2; return; }

	/* Second call also succeeds (idempotent) */
	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 3; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(ambient_limit_monotonic);
ATF_TC_BODY(ambient_limit_monotonic, tc)
{
	int r;

	r = in_child(ambient_limit_monotonic_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_ambient_limit should be idempotent (result=%d)", r);
}

/* ---- dup inherits noambient ---- */

static void
ambient_limit_dup_body(int *result)
{
	char buf[16];
	int fd, fd2;

	fd = open("/tmp/cap_pure_test_file7", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }
	if (write(fd, "hello", 5) != 5) { *result = 2; return; }

	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 3; return; }

	fd2 = dup(fd);
	if (fd2 < 0) { *result = 4; return; }

	if (cap_enter() != 0) { *result = 5; return; }

	/* dup'd fd should also have noambient — read should work */
	if (lseek(fd2, 0, SEEK_SET) != 0) { *result = 6; return; }
	if (read(fd2, buf, 5) != 5) { *result = 7; return; }
	if (memcmp(buf, "hello", 5) != 0) { *result = 8; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(ambient_limit_dup);
ATF_TC_BODY(ambient_limit_dup, tc)
{
	int r;

	r = in_child(ambient_limit_dup_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "dup should inherit noambient (result=%d)", r);
	unlink("/tmp/cap_pure_test_file7");
}

/* ---- Socket noambient ---- */

static void
ambient_limit_socket_body(int *result)
{
	char buf[16];
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}

	if (syscall(SYS_cap_ambient_limit, sv[0]) != 0) { *result = 2; return; }
	if (syscall(SYS_cap_ambient_limit, sv[1]) != 0) { *result = 3; return; }

	if (cap_enter() != 0) { *result = 4; return; }

	/* write then read on noambient sockets in cap mode */
	if (write(sv[0], "test", 4) != 4) { *result = 5; return; }
	if (read(sv[1], buf, 4) != 4) { *result = 6; return; }
	if (memcmp(buf, "test", 4) != 0) { *result = 7; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(ambient_limit_socket);
ATF_TC_BODY(ambient_limit_socket, tc)
{
	int r;

	r = in_child(ambient_limit_socket_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "socket read/write with noambient in cap mode (result=%d)", r);
}

/* ---- Pipe noambient ---- */

static void
ambient_limit_pipe_body(int *result)
{
	char buf[16];
	int pv[2];

	if (pipe(pv) != 0) { *result = 1; return; }

	if (syscall(SYS_cap_ambient_limit, pv[0]) != 0) { *result = 2; return; }
	if (syscall(SYS_cap_ambient_limit, pv[1]) != 0) { *result = 3; return; }

	if (cap_enter() != 0) { *result = 4; return; }

	if (write(pv[1], "pipe", 4) != 4) { *result = 5; return; }
	if (read(pv[0], buf, 4) != 4) { *result = 6; return; }
	if (memcmp(buf, "pipe", 4) != 0) { *result = 7; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(ambient_limit_pipe);
ATF_TC_BODY(ambient_limit_pipe, tc)
{
	int r;

	r = in_child(ambient_limit_pipe_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pipe read/write with noambient in cap mode (result=%d)", r);
}

/* ---- SIGTRAP for CAPREQUIRED outside cap mode ---- */

static volatile sig_atomic_t got_sigtrap = 0;

static void
sigtrap_handler(int sig __unused)
{
	got_sigtrap = 1;
}

static void
caprequired_sigtrap_body(int *result)
{
	struct sigaction sa;
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) { *result = 1; return; }

	/* Enable P2_TRAPCAP */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigtrap_handler;
	if (sigaction(SIGTRAP, &sa, NULL) != 0) { *result = 2; return; }

	/* Use procctl to set P2_TRAPCAP */
	int flag = PROC_TRAPCAP_CTL_ENABLE;
	if (procctl(P_PID, getpid(), PROC_TRAPCAP_CTL, &flag) != 0) {
		*result = 3; return;
	}

	got_sigtrap = 0;

	/* cap_fchmod outside cap mode should fail and deliver SIGTRAP */
	syscall(SYS_cap_fchmod, fd, 0600);

	if (!got_sigtrap) { *result = 4; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(caprequired_sigtrap);
ATF_TC_BODY(caprequired_sigtrap, tc)
{
	int r;

	r = in_child(caprequired_sigtrap_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "CAPREQUIRED outside cap mode should deliver SIGTRAP (result=%d)",
	    r);
}

/* ---- SCM_RIGHTS: non-cap receiver, marker inert ---- */

static void
scm_rights_noncap_body(int *result)
{
	int sv[2], fd, rfd;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char buf[1], cbuf[CMSG_SPACE(sizeof(int))];
	char data;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}
	fd = open("/tmp/cap_pure_scm_test", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 2; return; }
	if (write(fd, "x", 1) != 1) { *result = 3; return; }

	/* Mark fd as noambient */
	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 4; return; }

	/* Send the fd over SCM_RIGHTS */
	memset(&msg, 0, sizeof(msg));
	{
		static char a_buf[] = "A";
		iov.iov_base = a_buf;
	}
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	if (sendmsg(sv[0], &msg, 0) < 0) { *result = 5; return; }

	/* Receive the fd — we are NOT in cap mode */
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &data;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	if (recvmsg(sv[1], &msg, 0) < 0) { *result = 6; return; }
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL) { *result = 7; return; }
	memcpy(&rfd, CMSG_DATA(cmsg), sizeof(int));

	/* Read should work (not in cap mode, marker is inert,
	 * MAC fires normally — but no MAC policy loaded so it passes) */
	if (lseek(rfd, 0, SEEK_SET) != 0) { *result = 8; return; }
	if (read(rfd, buf, 1) != 1) { *result = 9; return; }

	close(rfd);
	close(fd);
	close(sv[0]);
	close(sv[1]);
	unlink("/tmp/cap_pure_scm_test");
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(scm_rights_noncap);
ATF_TC_BODY(scm_rights_noncap, tc)
{
	int r;

	r = in_child(scm_rights_noncap_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "SCM_RIGHTS to non-cap process (result=%d)", r);
}

/* ---- SCM_RIGHTS: cap-mode receiver, marker honored ---- */

static void
scm_rights_cap_body(int *result)
{
	int sv[2], fd, rfd;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char buf[1], cbuf[CMSG_SPACE(sizeof(int))];
	char data;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}
	fd = open("/tmp/cap_pure_scm_test2", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 2; return; }
	if (write(fd, "y", 1) != 1) { *result = 3; return; }

	/* Mark fd as noambient */
	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 4; return; }

	/* Send the fd */
	memset(&msg, 0, sizeof(msg));
	{
		static char b_buf[] = "B";
		iov.iov_base = b_buf;
	}
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	if (sendmsg(sv[0], &msg, 0) < 0) { *result = 5; return; }

	/* Enter cap mode before receiving */
	if (cap_enter() != 0) { *result = 6; return; }

	/* Receive the fd — we ARE in cap mode */
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &data;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	if (recvmsg(sv[1], &msg, 0) < 0) { *result = 7; return; }
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL) { *result = 8; return; }
	memcpy(&rfd, CMSG_DATA(cmsg), sizeof(int));

	/* Read should succeed — in cap mode with noambient marker */
	if (lseek(rfd, 0, SEEK_SET) != 0) { *result = 9; return; }
	if (read(rfd, buf, 1) != 1) { *result = 10; return; }
	if (buf[0] != 'y') { *result = 11; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(scm_rights_cap);
ATF_TC_BODY(scm_rights_cap, tc)
{
	int r;

	r = in_child(scm_rights_cap_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "SCM_RIGHTS to cap-mode process (result=%d)", r);
	unlink("/tmp/cap_pure_scm_test2");
}

/* ---- fork inherits noambient ---- */

static void
fork_inherit_body(int *result)
{
	pid_t pid;
	int fd, status;

	fd = open("/tmp/cap_pure_fork_test", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }
	if (write(fd, "fork", 4) != 4) { *result = 2; return; }

	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 3; return; }

	pid = fork();
	if (pid < 0) { *result = 4; return; }
	if (pid == 0) {
		char buf[4];

		/* Child: enter cap mode and try read */
		if (cap_enter() != 0) _exit(1);
		if (lseek(fd, 0, SEEK_SET) != 0) _exit(2);
		if (read(fd, buf, 4) != 4) _exit(3);
		if (memcmp(buf, "fork", 4) != 0) _exit(4);
		_exit(0);
	}
	if (waitpid(pid, &status, 0) != pid) { *result = 5; return; }
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		*result = 10 + WEXITSTATUS(status); return;
	}

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(fork_inherit);
ATF_TC_BODY(fork_inherit, tc)
{
	int r;

	r = in_child(fork_inherit_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "fork should inherit noambient (result=%d)", r);
	unlink("/tmp/cap_pure_fork_test");
}

/* ---- cap_ftruncate ---- */

static void
cap_ftruncate_body(int *result)
{
	struct stat sb;
	int fd;

	fd = open("/tmp/cap_pure_trunc_test", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }
	if (write(fd, "truncate_me", 11) != 11) { *result = 2; return; }

	if (cap_enter() != 0) { *result = 3; return; }

	/* cap_ftruncate should work in cap mode */
	if (syscall(SYS_cap_ftruncate, fd, (off_t)5) != 0) {
		*result = 4; return;
	}
	if (fstat(fd, &sb) != 0) { *result = 5; return; }
	if (sb.st_size != 5) { *result = 6; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_ftruncate_test);
ATF_TC_BODY(cap_ftruncate_test, tc)
{
	int r;

	r = in_child(cap_ftruncate_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_ftruncate in cap mode (result=%d)", r);
	unlink("/tmp/cap_pure_trunc_test");
}

/* ---- cap_ioctl ---- */

static void
cap_ioctl_body(int *result)
{
	int fd, nb;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) { *result = 1; return; }

	if (cap_enter() != 0) { *result = 2; return; }

	/* cap_ioctl FIONBIO should work */
	nb = 1;
	if (syscall(SYS_cap_ioctl, fd, FIONBIO, &nb) != 0) {
		*result = 3; return;
	}

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_ioctl_test);
ATF_TC_BODY(cap_ioctl_test, tc)
{
	int r;

	r = in_child(cap_ioctl_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_ioctl in cap mode (result=%d)", r);
}

/* ---- cap_mmap ---- */

static void
cap_mmap_body(int *result)
{
	void *addr;
	int fd;

	fd = open("/tmp/cap_pure_mmap_test", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }
	if (ftruncate(fd, 4096) != 0) { *result = 2; return; }

	if (cap_enter() != 0) { *result = 3; return; }

	/* cap_mmap should work in cap mode */
	addr = (void *)(uintptr_t)syscall(SYS_cap_mmap, (void *)NULL,
	    (size_t)4096, PROT_READ, MAP_PRIVATE, fd, (off_t)0);
	if (addr == MAP_FAILED) { *result = 4; return; }

	munmap(addr, 4096);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_mmap_test);
ATF_TC_BODY(cap_mmap_test, tc)
{
	int r;

	r = in_child(cap_mmap_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_mmap in cap mode (result=%d)", r);
	unlink("/tmp/cap_pure_mmap_test");
}

/* ---- cap_sendmsg / cap_recvmsg ---- */

static void
cap_sendrecv_body(int *result)
{
	int sv[2];
	struct msghdr msg;
	struct iovec iov;
	char buf[4];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}

	if (cap_enter() != 0) { *result = 2; return; }

	/* cap_sendmsg */
	memset(&msg, 0, sizeof(msg));
	{
		static char test_buf[] = "test";
		iov.iov_base = test_buf;
	}
	iov.iov_len = 4;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (syscall(SYS_cap_sendmsg, sv[0], &msg, 0) != 4) {
		*result = 3; return;
	}

	/* cap_recvmsg */
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buf;
	iov.iov_len = 4;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (syscall(SYS_cap_recvmsg, sv[1], &msg, 0) != 4) {
		*result = 4; return;
	}
	if (memcmp(buf, "test", 4) != 0) { *result = 5; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_sendrecv_test);
ATF_TC_BODY(cap_sendrecv_test, tc)
{
	int r;

	r = in_child(cap_sendrecv_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_sendmsg/cap_recvmsg in cap mode (result=%d)", r);
}

/* ---- AIO noambient ---- */

static void
aio_noambient_body(int *result)
{
	struct aiocb cb;
	char buf[5];
	int fd;

	fd = open("/tmp/cap_pure_aio_test", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }
	if (write(fd, "async", 5) != 5) { *result = 2; return; }

	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 3; return; }
	if (cap_enter() != 0) { *result = 4; return; }

	/* aio_read on noambient fd in cap mode */
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	cb.aio_buf = buf;
	cb.aio_nbytes = 5;
	cb.aio_offset = 0;

	if (aio_read(&cb) != 0) { *result = 5; return; }

	/* Wait for completion */
	while (aio_error(&cb) == EINPROGRESS)
		usleep(1000);

	if (aio_error(&cb) != 0) { *result = 6; return; }
	if (aio_return(&cb) != 5) { *result = 7; return; }
	if (memcmp(buf, "async", 5) != 0) { *result = 8; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(aio_noambient);
ATF_TC_BODY(aio_noambient, tc)
{
	int r;

	r = in_child(aio_noambient_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "AIO read with noambient in cap mode (result=%d)", r);
	unlink("/tmp/cap_pure_aio_test");
}

/* ---- pdself outside cap mode ---- */

static void
pdself_outside_capmode_body(int *result)
{
	int fd;

	/* pdself outside cap mode should fail with ENOTCAPABLE */
	if (pdself(&fd, 0) == 0) { *result = 2; return; }
	if (errno != ENOTCAPABLE) { *result = 3; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdself_outside_capmode);
ATF_TC_BODY(pdself_outside_capmode, tc)
{
	int r;

	r = in_child(pdself_outside_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdself outside cap mode: expected ENOTCAPABLE (result=%d)", r);
}

/* ---- pdself inside cap mode ---- */

static void
pdself_inside_capmode_body(int *result)
{
	pid_t pid;
	int fd;

	if (cap_enter() != 0) { *result = 1; return; }

	/* pdself inside cap mode should succeed */
	if (pdself(&fd, 0) != 0) { *result = 2; return; }
	if (fd < 0) { *result = 3; return; }

	/* pdgetpid on the descriptor should return our own pid */
	if (pdgetpid(fd, &pid) != 0) { *result = 4; return; }
	if (pid != getpid()) { *result = 5; return; }

	close(fd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdself_inside_capmode);
ATF_TC_BODY(pdself_inside_capmode, tc)
{
	int r;

	r = in_child(pdself_inside_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdself inside cap mode: expected success (result=%d)", r);
}

/* ---- pdself second call returns shared fd ---- */

static void
pdself_second_body(int *result)
{
	int fd, fd2;

	if (cap_enter() != 0) { *result = 1; return; }

	if (pdself(&fd, 0) != 0) { *result = 2; return; }

	/* Second pdself returns another fd for the same procdesc */
	if (pdself(&fd2, 0) != 0) { *result = 3; return; }
	if (fd2 < 0) { *result = 4; return; }
	if (fd2 == fd) { *result = 5; return; }

	close(fd2);
	close(fd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdself_second_call);
ATF_TC_BODY(pdself_second_call, tc)
{
	int r;

	r = in_child(pdself_second_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdself second call: expected shared fd (result=%d)", r);
}

/* ---- pdself invalid flags ---- */

static void
pdself_bad_flags_body(int *result)
{
	int fd;

	if (cap_enter() != 0) { *result = 1; return; }

	if (pdself(&fd, 0x100) == 0) { *result = 2; return; }
	if (errno != EINVAL) { *result = 3; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdself_bad_flags);
ATF_TC_BODY(pdself_bad_flags, tc)
{
	int r;

	r = in_child(pdself_bad_flags_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdself bad flags: expected EINVAL (result=%d)", r);
}

/* ---- pdself self-close is safe ---- */

static void
pdself_selfclose_body(int *result)
{
	int fd;

	if (cap_enter() != 0) { *result = 1; return; }

	if (pdself(&fd, 0) != 0) { *result = 2; return; }

	/*
	 * Closing our own procdesc should NOT kill us.
	 * If PDF_SELF close logic is broken, we die here and the
	 * parent sees a signal exit instead of clean _exit(0).
	 */
	close(fd);

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdself_selfclose);
ATF_TC_BODY(pdself_selfclose, tc)
{
	int r, status;

	r = in_child(pdself_selfclose_body, &status);
	ATF_REQUIRE_MSG(r == 0,
	    "pdself self-close should not kill process (result=%d, status=0x%x)",
	    r, status);
}

/* ---- pdcmp same process ---- */

static void
pdcmp_same_body(int *result)
{
	int fd, fd2, cmp;

	if (cap_enter() != 0) { *result = 1; return; }

	if (pdself(&fd, 0) != 0) { *result = 2; return; }

	/* dup the descriptor */
	fd2 = dup(fd);
	if (fd2 < 0) { *result = 3; return; }

	/* pdcmp on two fds for the same process should return 0 */
	if (pdcmp(fd, fd2, &cmp) != 0) { *result = 4; return; }
	if (cmp != 0) { *result = 5; return; }

	close(fd2);
	close(fd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdcmp_same);
ATF_TC_BODY(pdcmp_same, tc)
{
	int r;

	r = in_child(pdcmp_same_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdcmp same process: expected 0 (result=%d)", r);
}

/* ---- pdcmp different processes ---- */

static void
pdcmp_different_body(int *result)
{
	int fd1, fd2, cmp;
	pid_t pid;

	/* Create two children via pdfork — they are different processes */
	pid = pdfork(&fd1, 0);
	if (pid < 0) { *result = 1; return; }
	if (pid == 0)
		_exit(0);

	pid = pdfork(&fd2, 0);
	if (pid < 0) { *result = 2; return; }
	if (pid == 0)
		_exit(0);

	/* pdcmp on two different processes should return non-zero */
	if (pdcmp(fd1, fd2, &cmp) != 0) { *result = 3; return; }
	if (cmp == 0) { *result = 4; return; }

	close(fd2);
	close(fd1);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdcmp_different);
ATF_TC_BODY(pdcmp_different, tc)
{
	int r;

	r = in_child(pdcmp_different_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdcmp two different pdfork children (result=%d)", r);
}

/* ---- pdself on pdfork child returns shared fd ---- */

static void
pdself_pdfork_shared_body(int *result)
{
	int fd;
	pid_t pid;

	pid = pdfork(&fd, 0);
	if (pid < 0) { *result = 1; return; }
	if (pid == 0) {
		int myfd;

		/*
		 * pdfork child already has a procdesc; pdself should
		 * succeed and return a new fd sharing the same procdesc.
		 */
		if (cap_enter() != 0) _exit(1);
		if (pdself(&myfd, 0) != 0) _exit(2);
		if (myfd < 0) _exit(3);

		/* Closing our reference should not kill us (not last) */
		close(myfd);
		_exit(0);
	}

	/* Reap child via the procdesc */
	if (pdwait(fd, NULL, WEXITED, NULL, NULL) != 0) { *result = 2; return; }
	close(fd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdself_pdfork_shared);
ATF_TC_BODY(pdself_pdfork_shared, tc)
{
	int r;

	r = in_child(pdself_pdfork_shared_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdself in pdfork child: expected shared fd (result=%d)", r);
}

/* ---- pdself external close kills process ---- */

static void
pdself_external_kill_body(int *result)
{
	int sv[2], pipefd[2], fd;
	char buf;

	/*
	 * Fork a child that enters cap mode, creates a pdself descriptor,
	 * sends it to us over a socketpair, then closes its local copy
	 * and sleeps.  We close the received descriptor — as the last
	 * reference held by an external process, this should SIGKILL
	 * the child.
	 *
	 * Once the child has a procdesc it is managed via the descriptor
	 * (normal procdesc semantics: reparented to init on close, not
	 * visible to waitpid).  Use a pipe to detect death.
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}
	if (pipe(pipefd) != 0) { *result = 1; return; }

	switch (fork()) {
	case -1:
		*result = 2; return;
	case 0:
	    {
		struct msghdr msg;
		struct cmsghdr *cmsg;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		int myfd;

		struct iovec iov;
		char byte = 0;

		close(sv[0]);
		close(pipefd[0]);
		if (cap_enter() != 0) _exit(10);
		if (pdself(&myfd, 0) != 0) _exit(11);

		/* Send the procdesc fd to the parent */
		memset(&msg, 0, sizeof(msg));
		memset(&cmsgbuf, 0, sizeof(cmsgbuf));
		iov.iov_base = &byte;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &myfd, sizeof(int));
		msg.msg_controllen = cmsg->cmsg_len;
		if (sendmsg(sv[1], &msg, 0) < 0) _exit(12);

		/* Close our copy — parent still holds one */
		close(myfd);

		/* Sleep until killed */
		for (;;)
			sleep(60);
		_exit(99);
	    }
	}

	/* Parent */
	close(sv[1]);
	close(pipefd[1]);

	/* Receive the procdesc fd from the child */
	{
		struct msghdr msg;
		struct cmsghdr *cmsg;
		union {
			struct cmsghdr hdr;
			char buf[CMSG_SPACE(sizeof(int))];
		} cmsgbuf;
		char dummy;
		struct iovec iov;

		memset(&msg, 0, sizeof(msg));
		iov.iov_base = &dummy;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		if (recvmsg(sv[0], &msg, 0) < 0) {
			*result = 3; return;
		}
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL ||
		    cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS) {
			*result = 4; return;
		}
		memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	}
	close(sv[0]);

	/*
	 * Close the received procdesc — this is the last reference
	 * from an external process, so it should SIGKILL the child.
	 */
	close(fd);

	/* Pipe EOF confirms child died */
	if (read(pipefd[0], &buf, 1) != 0) {
		*result = 5; return;
	}
	close(pipefd[0]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdself_external_kill);
ATF_TC_BODY(pdself_external_kill, tc)
{
	int r;

	r = in_child(pdself_external_kill_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdself external close should SIGKILL child (result=%d)", r);
}

/* ---- pdcmp after process exit ---- */

ATF_TC_WITHOUT_HEAD(pdcmp_after_exit);
ATF_TC_BODY(pdcmp_after_exit, tc)
{
	int fd1, fd2, cmp;
	pid_t pid;

	/*
	 * Create two pdfork children, let them exit, then compare
	 * their process descriptors.  pd_pid is preserved after exit
	 * so pdcmp must still work correctly.
	 */
	pid = pdfork(&fd1, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);

	pid = pdfork(&fd2, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);

	/* Wait for both children to exit */
	ATF_REQUIRE(pdwait(fd1, NULL, WEXITED, NULL, NULL) == 0);
	ATF_REQUIRE(pdwait(fd2, NULL, WEXITED, NULL, NULL) == 0);

	/* pdcmp on two dead-but-distinct children: must be non-equal */
	ATF_REQUIRE(pdcmp(fd1, fd2, &cmp) == 0);
	ATF_REQUIRE_MSG(cmp != 0,
	    "pdcmp should report different after both children exited");

	/* pdcmp on the same dead child via dup: must be equal */
	{
		int fd1dup = dup(fd1);
		ATF_REQUIRE(fd1dup >= 0);
		ATF_REQUIRE(pdcmp(fd1, fd1dup, &cmp) == 0);
		ATF_REQUIRE_MSG(cmp == 0,
		    "pdcmp on dup'd fd of dead child should be equal");
		close(fd1dup);
	}

	close(fd2);
	close(fd1);
}

/* ---- pdcmp non-procdesc fd ---- */

static void
pdcmp_bad_fd_body(int *result)
{
	int fd, cmp;

	if (cap_enter() != 0) { *result = 1; return; }

	if (pdself(&fd, 0) != 0) { *result = 2; return; }

	/* pdcmp with a non-procdesc fd (stdin) should fail */
	if (pdcmp(fd, STDIN_FILENO, &cmp) == 0) {
		*result = 3; return;
	}
	if (errno != EINVAL) { *result = 4; return; }

	close(fd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdcmp_bad_fd);
ATF_TC_BODY(pdcmp_bad_fd, tc)
{
	int r;

	r = in_child(pdcmp_bad_fd_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdcmp with non-procdesc fd: expected EINVAL (result=%d)", r);
}

/* ---- pdself + pdwait: holder observes normal exit ---- */

ATF_TC_WITHOUT_HEAD(pdself_pdwait);
ATF_TC_BODY(pdself_pdwait, tc)
{
	int sv[2], fd, status;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	char dummy;
	struct iovec iov;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int myfd;
		char byte = 0;

		close(sv[0]);
		if (cap_enter() != 0) _exit(10);
		if (pdself(&myfd, 0) != 0) _exit(11);

		/* Send procdesc to parent */
		memset(&msg, 0, sizeof(msg));
		memset(&cmsgbuf, 0, sizeof(cmsgbuf));
		iov.iov_base = &byte;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &myfd, sizeof(int));
		msg.msg_controllen = cmsg->cmsg_len;
		if (sendmsg(sv[1], &msg, 0) < 0) _exit(12);

		close(myfd);
		_exit(42);
	}

	/* Parent: receive the procdesc */
	close(sv[1]);
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	ATF_REQUIRE(recvmsg(sv[0], &msg, 0) >= 0);
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL);
	ATF_REQUIRE(cmsg->cmsg_type == SCM_RIGHTS);
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	close(sv[0]);

	/* Use pdwait to observe the child's exit */
	ATF_REQUIRE_MSG(pdwait(fd, &status, WEXITED, NULL, NULL) == 0,
	    "pdwait failed: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 42,
	    "expected exit 42, got %d", WEXITSTATUS(status));
	close(fd);
}

/* ---- pdself + pdkill: holder sends signal ---- */

ATF_TC_WITHOUT_HEAD(pdself_pdkill);
ATF_TC_BODY(pdself_pdkill, tc)
{
	int sv[2], fd, status;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	char dummy;
	struct iovec iov;
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int myfd;
		char byte = 0;

		close(sv[0]);
		if (cap_enter() != 0) _exit(10);
		if (pdself(&myfd, 0) != 0) _exit(11);

		/* Send procdesc to parent */
		memset(&msg, 0, sizeof(msg));
		memset(&cmsgbuf, 0, sizeof(cmsgbuf));
		iov.iov_base = &byte;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &myfd, sizeof(int));
		msg.msg_controllen = cmsg->cmsg_len;
		if (sendmsg(sv[1], &msg, 0) < 0) _exit(12);

		close(myfd);
		/* Sleep until killed */
		for (;;)
			sleep(60);
		_exit(99);
	}

	/* Parent: receive the procdesc */
	close(sv[1]);
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	ATF_REQUIRE(recvmsg(sv[0], &msg, 0) >= 0);
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL);
	ATF_REQUIRE(cmsg->cmsg_type == SCM_RIGHTS);
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	close(sv[0]);

	/* Kill the child via pdkill */
	ATF_REQUIRE_MSG(pdkill(fd, SIGTERM) == 0,
	    "pdkill failed: %s", strerror(errno));

	/* Observe death via pdwait */
	ATF_REQUIRE(pdwait(fd, &status, WEXITED, NULL, NULL) == 0);
	ATF_REQUIRE(WIFSIGNALED(status));
	ATF_REQUIRE_MSG(WTERMSIG(status) == SIGTERM,
	    "expected SIGTERM, got signal %d", WTERMSIG(status));
	close(fd);
}

/* ---- ATF test program ---- */

ATF_TP_ADD_TCS(tp)
{

	/* CAPREQUIRED gate */
	ATF_TP_ADD_TC(tp, cap_fchmod_outside_capmode);
	ATF_TP_ADD_TC(tp, cap_fchmod_inside_capmode);
	ATF_TP_ADD_TC(tp, cap_fchmod_nonvnode);
	ATF_TP_ADD_TC(tp, cap_fchmod_rights);

	/* Existing behavior unchanged */
	ATF_TP_ADD_TC(tp, ambient_fchmod_unchanged);

	/* cap_ambient_limit */
	ATF_TP_ADD_TC(tp, ambient_limit_outside_capmode);
	ATF_TP_ADD_TC(tp, ambient_limit_inside_capmode);
	ATF_TP_ADD_TC(tp, ambient_limit_bad_fd);
	ATF_TP_ADD_TC(tp, ambient_limit_monotonic);
	ATF_TP_ADD_TC(tp, ambient_limit_dup);
	ATF_TP_ADD_TC(tp, ambient_limit_socket);
	ATF_TP_ADD_TC(tp, ambient_limit_pipe);

	/* SIGTRAP */
	ATF_TP_ADD_TC(tp, caprequired_sigtrap);

	/* SCM_RIGHTS */
	ATF_TP_ADD_TC(tp, scm_rights_noncap);
	ATF_TP_ADD_TC(tp, scm_rights_cap);

	/* Fork */
	ATF_TP_ADD_TC(tp, fork_inherit);

	/* Tier 2+3 cap_* syscalls */
	ATF_TP_ADD_TC(tp, cap_ftruncate_test);
	ATF_TP_ADD_TC(tp, cap_ioctl_test);
	ATF_TP_ADD_TC(tp, cap_mmap_test);
	ATF_TP_ADD_TC(tp, cap_sendrecv_test);

	/* AIO */
	ATF_TP_ADD_TC(tp, aio_noambient);

	/* pdself / pdcmp */
	ATF_TP_ADD_TC(tp, pdself_outside_capmode);
	ATF_TP_ADD_TC(tp, pdself_inside_capmode);
	ATF_TP_ADD_TC(tp, pdself_second_call);
	ATF_TP_ADD_TC(tp, pdself_bad_flags);
	ATF_TP_ADD_TC(tp, pdself_selfclose);
	ATF_TP_ADD_TC(tp, pdcmp_same);
	ATF_TP_ADD_TC(tp, pdcmp_different);
	ATF_TP_ADD_TC(tp, pdself_external_kill);
	ATF_TP_ADD_TC(tp, pdcmp_after_exit);
	ATF_TP_ADD_TC(tp, pdcmp_bad_fd);
	ATF_TP_ADD_TC(tp, pdself_pdfork_shared);
	ATF_TP_ADD_TC(tp, pdself_pdwait);
	ATF_TP_ADD_TC(tp, pdself_pdkill);

	return (atf_no_error());
}
