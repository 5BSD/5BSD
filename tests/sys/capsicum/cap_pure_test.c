/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Tests for CAP_SUFFICIENT descriptor flag (cap_ambient_limit) and
 * capability-mode enforcement.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
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
#include <sys/jail.h>
#include <sys/filio.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <aio.h>

#ifndef SYS_pdself
#define	SYS_pdself		630
#endif
#ifndef SYS_pdcmp
#define	SYS_pdcmp		631
#endif

/*
 * Shims for syscalls not yet in the installed libsys (pkgbase lag).
 * The header declares them but the library may lack the symbols.
 */
#define	pdself(fdp, flags)	syscall(SYS_pdself, (fdp), (flags))
#define	pdcmp(a, b, res)	syscall(SYS_pdcmp, (a), (b), (res))
#ifndef SYS_cap_ambient_limit
#define	SYS_cap_ambient_limit	629
#endif
#ifndef SYS_pdincapmode
#define	SYS_pdincapmode		633
#endif
#ifndef NOTE_CAPMODE
#define	NOTE_CAPMODE		0x10000000
#endif
#ifndef NOTE_JAILED
#define	NOTE_JAILED		0x08000000
#endif
#ifndef NOTE_SETUID
#define	NOTE_SETUID		0x04000000
#endif
#ifndef NOTE_CHROOT
#define	NOTE_CHROOT		0x02000000
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

	/* Set CAP_SUFFICIENT outside cap mode */
	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 4; return; }

	/* Outside cap mode, read should still work (flag is inert) */
	if (read(fd, buf, 5) != 5) { *result = 5; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(ambient_limit_outside_capmode);
ATF_TC_BODY(ambient_limit_outside_capmode, tc)
{
	int r;

	r = in_child(ambient_limit_outside_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "CAP_SUFFICIENT flag should be inert outside cap mode (result=%d)", r);
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

	/* Set CAP_SUFFICIENT then enter cap mode */
	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 4; return; }
	if (cap_enter() != 0) { *result = 5; return; }

	/* read should succeed (MAC skipped in cap mode with CAP_SUFFICIENT) */
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
	    "CAP_SUFFICIENT read/write in cap mode (result=%d)", r);
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

/* ---- dup inherits CAP_SUFFICIENT ---- */

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

	/* dup'd fd should also have CAP_SUFFICIENT -- read should work */
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
	    "dup should inherit CAP_SUFFICIENT (result=%d)", r);
	unlink("/tmp/cap_pure_test_file7");
}

/* ---- Socket CAP_SUFFICIENT ---- */

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

	/* write then read on CAP_SUFFICIENT sockets in cap mode */
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
	    "socket read/write with CAP_SUFFICIENT in cap mode (result=%d)", r);
}

/* ---- Pipe CAP_SUFFICIENT ---- */

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
	    "pipe read/write with CAP_SUFFICIENT in cap mode (result=%d)", r);
}

/* ---- SCM_RIGHTS: non-cap receiver, flag inert ---- */

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

	/* Mark fd as CAP_SUFFICIENT */
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

	/* Read should work (not in cap mode, flag is inert,
	 * MAC fires normally -- but no MAC policy loaded so it passes) */
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

/* ---- SCM_RIGHTS: cap-mode receiver, flag honored ---- */

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

	/* Mark fd as CAP_SUFFICIENT */
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

	/* Read should succeed -- in cap mode with CAP_SUFFICIENT flag */
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

/* ---- fork inherits CAP_SUFFICIENT ---- */

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
	    "fork should inherit CAP_SUFFICIENT (result=%d)", r);
	unlink("/tmp/cap_pure_fork_test");
}

/* ---- AIO CAP_SUFFICIENT ---- */

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

	/* aio_read on CAP_SUFFICIENT fd in cap mode */
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
	    "AIO read with CAP_SUFFICIENT in cap mode (result=%d)", r);
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
	if (errno != EBADF) { *result = 4; return; }

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

/*
 * Helper: build and send one fd over a socketpair.
 * sv[0] is the sender socket, sv[1] is the receiver socket.
 * Returns 0 on success, non-zero on failure.
 */
static int __unused
send_fd_over_sock(int sender, int fd_to_send)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))];
	static char byte = 'X';

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
	return (sendmsg(sender, &msg, 0) < 0 ? -1 : 0);
}

/*
 * Helper: receive one fd from a socket.
 * Returns the received fd on success, -1 on failure.
 */
static int __unused
recv_fd_from_sock(int receiver)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	int rfd;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	if (recvmsg(receiver, &msg, 0) < 0)
		return (-1);
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
		return (-1);
	memcpy(&rfd, CMSG_DATA(cmsg), sizeof(int));
	return (rfd);
}

/* ---- pdincapmode tests ---- */

/*
 * pdincapmode_before_capenter:
 * pdfork a child that does NOT enter cap mode.  Verify pdincapmode
 * returns 0.
 */
static void
pdincapmode_before_capenter_body(int *result)
{
	int pdfd;
	pid_t pid;

	pid = pdfork(&pdfd, 0);
	if (pid < 0) { *result = 1; return; }
	if (pid == 0) {
		/* Child: just sleep */
		sleep(60);
		_exit(0);
	}

	/* Parent: query cap mode — should be 0 */
	if (syscall(SYS_pdincapmode, pdfd) != 0) { *result = 2; return; }

	pdkill(pdfd, SIGKILL);
	close(pdfd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdincapmode_before_capenter);
ATF_TC_BODY(pdincapmode_before_capenter, tc)
{
	int r;

	r = in_child(pdincapmode_before_capenter_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdincapmode before cap_enter: expected 0 (result=%d)", r);
}

/*
 * pdincapmode_after_capenter:
 * pdfork a child that enters cap mode immediately.  Use a pipe for
 * synchronization.  Verify pdincapmode returns 1.
 */
static void
pdincapmode_after_capenter_body(int *result)
{
	int pdfd, pv[2];
	pid_t pid;
	char byte;

	if (pipe(pv) != 0) { *result = 1; return; }

	pid = pdfork(&pdfd, 0);
	if (pid < 0) { *result = 2; return; }
	if (pid == 0) {
		close(pv[0]);
		/* Enter cap mode, then signal parent */
		if (cap_enter() != 0) _exit(1);
		write(pv[1], "x", 1);
		close(pv[1]);
		sleep(60);
		_exit(0);
	}

	close(pv[1]);
	/* Wait for child to enter cap mode */
	if (read(pv[0], &byte, 1) != 1) { *result = 3; return; }
	close(pv[0]);

	/* Parent: query cap mode — should be 1 */
	if (syscall(SYS_pdincapmode, pdfd) != 1) { *result = 4; return; }

	pdkill(pdfd, SIGKILL);
	close(pdfd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(pdincapmode_after_capenter);
ATF_TC_BODY(pdincapmode_after_capenter, tc)
{
	int r;

	r = in_child(pdincapmode_after_capenter_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "pdincapmode after cap_enter: expected 1 (result=%d)", r);
}

/*
 * pdincapmode_bad_fd:
 * Verify EBADF for invalid descriptors and non-procdesc descriptors.
 */
ATF_TC_WITHOUT_HEAD(pdincapmode_bad_fd);
ATF_TC_BODY(pdincapmode_bad_fd, tc)
{
	int pv[2];

	/* Bad fd */
	ATF_REQUIRE(syscall(SYS_pdincapmode, -1) == -1);
	ATF_REQUIRE(errno == EBADF);

	/* Non-procdesc fd (pipe) */
	ATF_REQUIRE(pipe(pv) == 0);
	ATF_REQUIRE(syscall(SYS_pdincapmode, pv[0]) == -1);
	ATF_REQUIRE(errno == EBADF);
	close(pv[0]);
	close(pv[1]);
}

/* ---- NOTE_CAPMODE kqueue event test ---- */

/*
 * note_capmode_kevent:
 * pdfork a child, register EVFILT_PROCDESC with NOTE_CAPMODE on the
 * procdesc fd.  Child enters cap_enter() then sleeps.  Parent calls
 * kevent with a timeout.  Verify the event fires with NOTE_CAPMODE
 * in fflags.
 */
static void
note_capmode_kevent_body(int *result)
{
	int pdfd, kq, pv[2];
	struct kevent kev;
	struct timespec ts;
	pid_t pid;
	char byte;

	if (pipe(pv) != 0) { *result = 1; return; }

	pid = pdfork(&pdfd, 0);
	if (pid < 0) { *result = 2; return; }
	if (pid == 0) {
		/*
		 * Child: wait for parent to register the kevent, then
		 * enter cap mode and sleep.
		 */
		close(pv[1]);
		if (read(pv[0], &byte, 1) != 1) _exit(1);
		close(pv[0]);
		if (cap_enter() != 0) _exit(2);
		sleep(60);
		_exit(0);
	}

	close(pv[0]);

	kq = kqueue();
	if (kq < 0) { *result = 3; return; }

	EV_SET(&kev, pdfd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
	    NOTE_CAPMODE, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0) { *result = 4; return; }

	/* Signal child that the kevent is registered */
	write(pv[1], "x", 1);
	close(pv[1]);

	/* Wait up to 5 seconds for the event */
	ts.tv_sec = 5;
	ts.tv_nsec = 0;
	if (kevent(kq, NULL, 0, &kev, 1, &ts) != 1) { *result = 5; return; }

	if (kev.filter != EVFILT_PROCDESC) { *result = 6; return; }
	if ((kev.fflags & NOTE_CAPMODE) == 0) { *result = 7; return; }

	close(kq);
	pdkill(pdfd, SIGKILL);
	close(pdfd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(note_capmode_kevent);
ATF_TC_BODY(note_capmode_kevent, tc)
{
	int r;

	r = in_child(note_capmode_kevent_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "NOTE_CAPMODE kevent: expected event with NOTE_CAPMODE (result=%d)",
	    r);
}

/* ---- LOCAL_CAP_CONNECT tests ---- */

#ifndef LOCAL_CAP_CONNECT
#define	LOCAL_CAP_CONNECT	4
#endif

/*
 * capmode_connect_denied:
 * Set LOCAL_CAP_CONNECT on a listening socket. A non-cap-mode child
 * attempts to connect; verify ENOTCAPABLE.
 */
static void
capmode_connect_denied_body(int *result)
{
	struct sockaddr_un sun;
	char dir[] = "/tmp/cap_pure_test.XXXXXX";
	char path[128];
	int ls, cs, one = 1;

	if (mkdtemp(dir) == NULL) { *result = 1; return; }
	snprintf(path, sizeof(path), "%s/sock", dir);

	ls = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ls < 0) { *result = 2; return; }

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (bind(ls, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		*result = 3; return;
	}
	if (setsockopt(ls, 0, LOCAL_CAP_CONNECT, &one, sizeof(one)) != 0) {
		*result = 4; return;
	}
	if (listen(ls, 1) != 0) { *result = 5; return; }

	/* We are NOT in cap mode — connect must fail with ENOTCAPABLE */
	cs = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cs < 0) { *result = 6; return; }
	if (connect(cs, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
		*result = 7; return;
	}
	if (errno != ENOTCAPABLE) { *result = 8; return; }

	close(cs);
	close(ls);
	(void)unlink(path);
	(void)rmdir(dir);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(capmode_connect_denied);
ATF_TC_BODY(capmode_connect_denied, tc)
{
	int r;

	r = in_child(capmode_connect_denied_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "non-cap-mode connect must fail with ENOTCAPABLE (result=%d)", r);
}

/*
 * capmode_connect_allowed:
 * Set LOCAL_CAP_CONNECT on a listening socket. A child that enters
 * cap mode uses connectat() with a pre-opened dirfd to connect
 * successfully.
 */
static void
capmode_connect_allowed_body(int *result)
{
	struct sockaddr_un sun;
	char dir[] = "/tmp/cap_pure_test.XXXXXX";
	int ls, cs, dfd, as, one = 1;
	pid_t pid;
	int status;

	if (mkdtemp(dir) == NULL) { *result = 1; return; }

	ls = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ls < 0) { *result = 2; return; }

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/sock", dir);

	if (bind(ls, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		*result = 3; return;
	}
	if (setsockopt(ls, 0, LOCAL_CAP_CONNECT, &one, sizeof(one)) != 0) {
		*result = 4; return;
	}
	if (listen(ls, 1) != 0) { *result = 5; return; }

	/* Open dirfd BEFORE forking */
	dfd = open(dir, O_RDONLY | O_DIRECTORY);
	if (dfd < 0) { *result = 6; return; }

	pid = fork();
	if (pid < 0) { *result = 7; return; }
	if (pid == 0) {
		/* Child: enter cap mode, connectat with relative path */
		struct sockaddr_un csun;

		close(ls);
		cs = socket(AF_UNIX, SOCK_STREAM, 0);
		if (cs < 0) _exit(10);

		if (cap_enter() != 0) _exit(11);

		memset(&csun, 0, sizeof(csun));
		csun.sun_family = AF_UNIX;
		csun.sun_len = sizeof(csun);
		strlcpy(csun.sun_path, "sock", sizeof(csun.sun_path));

		if (connectat(dfd, cs, (struct sockaddr *)&csun,
		    sizeof(csun)) != 0)
			_exit(12);

		close(cs);
		close(dfd);
		_exit(0);
	}

	/* Parent: accept the connection */
	as = accept(ls, NULL, NULL);
	if (as < 0) { *result = 8; return; }

	if (waitpid(pid, &status, 0) != pid) { *result = 9; return; }
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		*result = 20 + WEXITSTATUS(status); return;
	}

	close(as);
	close(ls);
	close(dfd);
	(void)unlink(sun.sun_path);
	(void)rmdir(dir);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(capmode_connect_allowed);
ATF_TC_BODY(capmode_connect_allowed, tc)
{
	int r;

	r = in_child(capmode_connect_allowed_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap-mode connectat must succeed (result=%d)", r);
}

/*
 * capmode_connect_monotonic:
 * Set LOCAL_CAP_CONNECT, then try to clear it. Verify ENOTCAPABLE.
 */
static void
capmode_connect_monotonic_body(int *result)
{
	int s, one = 1, zero = 0;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) { *result = 1; return; }

	if (setsockopt(s, 0, LOCAL_CAP_CONNECT, &one, sizeof(one)) != 0) {
		*result = 2; return;
	}

	/* Attempt to clear — must fail with ENOTCAPABLE */
	if (setsockopt(s, 0, LOCAL_CAP_CONNECT, &zero, sizeof(zero)) == 0) {
		*result = 3; return;
	}
	if (errno != ENOTCAPABLE) { *result = 4; return; }

	/* Setting it again (idempotent) must succeed */
	if (setsockopt(s, 0, LOCAL_CAP_CONNECT, &one, sizeof(one)) != 0) {
		*result = 5; return;
	}

	close(s);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(capmode_connect_monotonic);
ATF_TC_BODY(capmode_connect_monotonic, tc)
{
	int r;

	r = in_child(capmode_connect_monotonic_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "LOCAL_CAP_CONNECT must be monotonic (result=%d)", r);
}

/* ---- LOCAL_CAP_CONNECT DGRAM test ---- */

/*
 * capmode_connect_dgram:
 * Verify LOCAL_CAP_CONNECT also works on SOCK_DGRAM sockets.
 * A non-cap-mode sendto() to a capmode-only DGRAM socket must fail.
 */
static void
capmode_connect_dgram_body(int *result)
{
	struct sockaddr_un sun;
	char dir[] = "/tmp/cap_pure_test.XXXXXX";
	char path[128];
	int ls, cs, one = 1;

	if (mkdtemp(dir) == NULL) { *result = 1; return; }
	snprintf(path, sizeof(path), "%s/dg", dir);

	ls = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ls < 0) { *result = 2; return; }

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (bind(ls, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		*result = 3; return;
	}
	if (setsockopt(ls, 0, LOCAL_CAP_CONNECT, &one, sizeof(one)) != 0) {
		*result = 4; return;
	}

	/* DGRAM: sendto goes through unp_connectat — must be denied */
	cs = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (cs < 0) { *result = 5; return; }
	if (sendto(cs, "x", 1, 0, (struct sockaddr *)&sun, sizeof(sun)) != -1) {
		*result = 6; return;
	}
	if (errno != ENOTCAPABLE) { *result = 7; return; }

	close(cs);
	close(ls);
	(void)unlink(path);
	(void)rmdir(dir);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(capmode_connect_dgram);
ATF_TC_BODY(capmode_connect_dgram, tc)
{
	int r;

	r = in_child(capmode_connect_dgram_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "DGRAM sendto to capmode-only socket must fail (result=%d)", r);
}

/* ---- pdincapmode ESRCH test ---- */

/*
 * pdincapmode_exited:
 * Verify pdincapmode returns ESRCH when the described process has exited.
 */
ATF_TC_WITHOUT_HEAD(pdincapmode_exited);
ATF_TC_BODY(pdincapmode_exited, tc)
{
	int pdfd, status;
	pid_t pid;

	pid = pdfork(&pdfd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);	/* child exits immediately */

	/* Wait for child to exit */
	ATF_REQUIRE(pdwait(pdfd, &status, WEXITED, NULL, NULL) == 0);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* Process has exited — pdincapmode should return ESRCH */
	ATF_REQUIRE(syscall(SYS_pdincapmode, pdfd) == -1);
	ATF_REQUIRE(errno == ESRCH);

	close(pdfd);
}

/* ---- cap_mmap_capmode tests ---- */

#ifndef SYS_cap_mmap_capmode
#define	SYS_cap_mmap_capmode	634
#endif
#ifndef SYS_cap_lookup_capmode
#define	SYS_cap_lookup_capmode	635
#endif

/*
 * mmap_capmode_denied:
 * shm_open, cap_mmap_capmode(fd), mmap outside cap mode -> ENOTCAPABLE
 */
static void
mmap_capmode_denied_body(int *result)
{
	int fd;
	void *addr;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	if (fd < 0) { *result = 1; return; }
	if (ftruncate(fd, 4096) != 0) { *result = 2; return; }

	if (syscall(SYS_cap_mmap_capmode, fd) != 0) { *result = 3; return; }

	/* mmap outside cap mode should fail */
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr != MAP_FAILED) {
		munmap(addr, 4096);
		*result = 4; return;
	}
	if (errno != ENOTCAPABLE) { *result = 5; return; }

	close(fd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(mmap_capmode_denied);
ATF_TC_BODY(mmap_capmode_denied, tc)
{
	int r;

	r = in_child(mmap_capmode_denied_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "mmap outside cap mode on capmode fd: expected ENOTCAPABLE (result=%d)",
	    r);
}

/*
 * mmap_capmode_allowed:
 * shm_open, cap_mmap_capmode(fd), enter cap mode, mmap -> succeeds
 */
static void
mmap_capmode_allowed_body(int *result)
{
	int fd;
	void *addr;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	if (fd < 0) { *result = 1; return; }
	if (ftruncate(fd, 4096) != 0) { *result = 2; return; }

	if (syscall(SYS_cap_mmap_capmode, fd) != 0) { *result = 3; return; }

	if (cap_enter() != 0) { *result = 4; return; }

	/* mmap in cap mode should succeed */
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) { *result = 5; return; }

	munmap(addr, 4096);
	close(fd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(mmap_capmode_allowed);
ATF_TC_BODY(mmap_capmode_allowed, tc)
{
	int r;

	r = in_child(mmap_capmode_allowed_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "mmap in cap mode on capmode fd: expected success (result=%d)", r);
}

/*
 * mmap_capmode_bad_fd:
 * cap_mmap_capmode on invalid fd -> EBADF
 */
static void
mmap_capmode_bad_fd_body(int *result)
{
	if (syscall(SYS_cap_mmap_capmode, 999) == 0) { *result = 1; return; }
	if (errno != EBADF) { *result = 2; return; }
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(mmap_capmode_bad_fd);
ATF_TC_BODY(mmap_capmode_bad_fd, tc)
{
	int r;

	r = in_child(mmap_capmode_bad_fd_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_mmap_capmode bad fd: expected EBADF (result=%d)", r);
}

/* ---- LOCAL_CAP_REQ tests ---- */

#ifndef LOCAL_CAP_REQ
#define	LOCAL_CAP_REQ		7
#endif

/*
 * cap_req_send_denied:
 * Set LOCAL_CAP_REQ on a socketpair. A non-cap-mode process tries to
 * send; verify ENOTCAPABLE.
 */
static void
cap_req_send_denied_body(int *result)
{
	int sv[2], one = 1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}
	if (setsockopt(sv[0], 0, LOCAL_CAP_REQ, &one, sizeof(one)) != 0) {
		*result = 2; return;
	}
	/* Not in cap mode — send must fail */
	if (send(sv[0], "x", 1, 0) != -1) { *result = 3; return; }
	if (errno != ENOTCAPABLE) { *result = 4; return; }

	close(sv[0]); close(sv[1]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_req_send_denied);
ATF_TC_BODY(cap_req_send_denied, tc)
{
	int r;

	r = in_child(cap_req_send_denied_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "LOCAL_CAP_REQ send outside capmode must fail (result=%d)", r);
}

/*
 * cap_req_recv_denied:
 * Set LOCAL_CAP_REQ on a socketpair. A non-cap-mode process tries to
 * recv; verify ENOTCAPABLE.
 */
static void
cap_req_recv_denied_body(int *result)
{
	int sv[2], one = 1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}
	if (setsockopt(sv[0], 0, LOCAL_CAP_REQ, &one, sizeof(one)) != 0) {
		*result = 2; return;
	}
	/* Send data from sv[1] so there's something to receive */
	if (send(sv[1], "x", 1, 0) != 1) { *result = 3; return; }

	/* Not in cap mode — recv on sv[0] must fail */
	{
		char buf[1];
		if (recv(sv[0], buf, 1, 0) != -1) { *result = 4; return; }
		if (errno != ENOTCAPABLE) { *result = 5; return; }
	}

	close(sv[0]); close(sv[1]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_req_recv_denied);
ATF_TC_BODY(cap_req_recv_denied, tc)
{
	int r;

	r = in_child(cap_req_recv_denied_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "LOCAL_CAP_REQ recv outside capmode must fail (result=%d)", r);
}

/*
 * cap_req_allowed:
 * Set LOCAL_CAP_REQ on a socketpair, enter cap mode, verify send/recv
 * succeed.
 */
static void
cap_req_allowed_body(int *result)
{
	int sv[2], one = 1;
	char buf[4];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}
	if (setsockopt(sv[0], 0, LOCAL_CAP_REQ, &one, sizeof(one)) != 0) {
		*result = 2; return;
	}
	if (setsockopt(sv[1], 0, LOCAL_CAP_REQ, &one, sizeof(one)) != 0) {
		*result = 3; return;
	}
	if (cap_enter() != 0) { *result = 4; return; }

	/* In cap mode — send and recv must succeed */
	if (send(sv[0], "test", 4, 0) != 4) { *result = 5; return; }
	if (recv(sv[1], buf, 4, 0) != 4) { *result = 6; return; }
	if (memcmp(buf, "test", 4) != 0) { *result = 7; return; }

	close(sv[0]); close(sv[1]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_req_allowed);
ATF_TC_BODY(cap_req_allowed, tc)
{
	int r;

	r = in_child(cap_req_allowed_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "LOCAL_CAP_REQ send/recv in capmode must succeed (result=%d)", r);
}

/*
 * cap_req_monotonic:
 * Once LOCAL_CAP_REQ is set, attempting to clear it must fail.
 */
static void
cap_req_monotonic_body(int *result)
{
	int sv[2], one = 1, zero = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}
	if (setsockopt(sv[0], 0, LOCAL_CAP_REQ, &one, sizeof(one)) != 0) {
		*result = 2; return;
	}
	/* Attempt to clear — must fail */
	if (setsockopt(sv[0], 0, LOCAL_CAP_REQ, &zero, sizeof(zero)) == 0) {
		*result = 3; return;
	}
	if (errno != ENOTCAPABLE) { *result = 4; return; }

	close(sv[0]); close(sv[1]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_req_monotonic);
ATF_TC_BODY(cap_req_monotonic, tc)
{
	int r;

	r = in_child(cap_req_monotonic_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "LOCAL_CAP_REQ must be monotonic (result=%d)", r);
}

/*
 * cap_req_dgram:
 * Verify LOCAL_CAP_REQ also works for SOCK_DGRAM sockets.
 */
static void
cap_req_dgram_body(int *result)
{
	int sv[2], one = 1;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
		*result = 1; return;
	}
	if (setsockopt(sv[0], 0, LOCAL_CAP_REQ, &one, sizeof(one)) != 0) {
		*result = 2; return;
	}
	/* Not in cap mode — send must fail */
	if (send(sv[0], "x", 1, 0) != -1) { *result = 3; return; }
	if (errno != ENOTCAPABLE) { *result = 4; return; }

	close(sv[0]); close(sv[1]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_req_dgram);
ATF_TC_BODY(cap_req_dgram, tc)
{
	int r;

	r = in_child(cap_req_dgram_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "LOCAL_CAP_REQ dgram send outside capmode must fail (result=%d)", r);
}

/* ---- cap_lookup_capmode tests ---- */

/*
 * lookup_capmode_denied:
 * open(".", O_DIRECTORY), cap_lookup_capmode(dirfd),
 * openat(dirfd, ...) outside cap mode -> ENOTCAPABLE
 */
static void
lookup_capmode_denied_body(int *result)
{
	int dirfd, fd;
	char dir[] = "/tmp/cap_lookup_test.XXXXXX";

	if (mkdtemp(dir) == NULL) { *result = 1; return; }

	dirfd = open(dir, O_DIRECTORY | O_RDONLY);
	if (dirfd < 0) { *result = 2; return; }

	/* Create a test file in the directory */
	fd = openat(dirfd, "testfile", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 3; return; }
	close(fd);

	if (syscall(SYS_cap_lookup_capmode, dirfd) != 0) {
		*result = 4; return;
	}

	/* openat outside cap mode should fail */
	fd = openat(dirfd, "testfile", O_RDONLY);
	if (fd >= 0) {
		close(fd);
		*result = 5; return;
	}
	if (errno != ENOTCAPABLE) { *result = 6; return; }

	close(dirfd);
	{
		char path[256];
		snprintf(path, sizeof(path), "%s/testfile", dir);
		(void)unlink(path);
	}
	(void)rmdir(dir);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(lookup_capmode_denied);
ATF_TC_BODY(lookup_capmode_denied, tc)
{
	int r;

	r = in_child(lookup_capmode_denied_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "openat outside cap mode on capmode dirfd: expected ENOTCAPABLE (result=%d)",
	    r);
}

/*
 * lookup_capmode_allowed:
 * open dir, cap_lookup_capmode(dirfd), enter cap mode,
 * openat(dirfd, ...) -> succeeds
 */
static void
lookup_capmode_allowed_body(int *result)
{
	int dirfd, fd;
	char dir[] = "/tmp/cap_lookup_ok.XXXXXX";

	if (mkdtemp(dir) == NULL) { *result = 1; return; }

	dirfd = open(dir, O_DIRECTORY | O_RDONLY);
	if (dirfd < 0) { *result = 2; return; }

	/* Create a test file in the directory */
	fd = openat(dirfd, "testfile", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 3; return; }
	close(fd);

	if (syscall(SYS_cap_lookup_capmode, dirfd) != 0) {
		*result = 4; return;
	}

	if (cap_enter() != 0) { *result = 5; return; }

	/* openat in cap mode should succeed */
	fd = openat(dirfd, "testfile", O_RDONLY);
	if (fd < 0) { *result = 6; return; }
	close(fd);

	close(dirfd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(lookup_capmode_allowed);
ATF_TC_BODY(lookup_capmode_allowed, tc)
{
	int r;

	r = in_child(lookup_capmode_allowed_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "openat in cap mode on capmode dirfd: expected success (result=%d)", r);
}

/*
 * lookup_capmode_bad_fd:
 * cap_lookup_capmode on invalid fd -> EBADF
 */
static void
lookup_capmode_bad_fd_body(int *result)
{
	if (syscall(SYS_cap_lookup_capmode, 999) == 0) { *result = 1; return; }
	if (errno != EBADF) { *result = 2; return; }
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(lookup_capmode_bad_fd);
ATF_TC_BODY(lookup_capmode_bad_fd, tc)
{
	int r;

	r = in_child(lookup_capmode_bad_fd_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_lookup_capmode bad fd: expected EBADF (result=%d)", r);
}

/* ---- LOCAL_CAPMODE_SERVER tests ---- */

#ifndef LOCAL_CAPMODE_SERVER
#define	LOCAL_CAPMODE_SERVER	6
#endif

/*
 * capmode_server_denied:
 * Client sets LOCAL_CAPMODE_SERVER on its socket, then tries to connect
 * to a server that is NOT in cap mode.  Connect must fail with ENOTCAPABLE.
 */
static void
capmode_server_denied_body(int *result)
{
	struct sockaddr_un sun;
	char dir[] = "/tmp/cap_pure_test.XXXXXX";
	char path[128];
	int ls, cs, one = 1;

	if (mkdtemp(dir) == NULL) { *result = 1; return; }
	snprintf(path, sizeof(path), "%s/sock", dir);

	ls = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ls < 0) { *result = 2; return; }

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (bind(ls, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		*result = 3; return;
	}
	if (listen(ls, 1) != 0) { *result = 4; return; }

	/* Client sets LOCAL_CAPMODE_SERVER before connecting */
	cs = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cs < 0) { *result = 5; return; }
	if (setsockopt(cs, 0, LOCAL_CAPMODE_SERVER, &one, sizeof(one)) != 0) {
		*result = 6; return;
	}

	/* Server is NOT in cap mode — connect must fail */
	if (connect(cs, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
		*result = 7; return;
	}
	if (errno != ENOTCAPABLE) { *result = 8; return; }

	close(cs);
	close(ls);
	(void)unlink(path);
	(void)rmdir(dir);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(capmode_server_denied);
ATF_TC_BODY(capmode_server_denied, tc)
{
	int r;

	r = in_child(capmode_server_denied_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "connect to non-cap-mode server must fail (result=%d)", r);
}

/*
 * capmode_server_monotonic:
 * Set LOCAL_CAPMODE_SERVER, then try to clear it.  Verify ENOTCAPABLE.
 */
static void
capmode_server_monotonic_body(int *result)
{
	int s, one = 1, zero = 0;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) { *result = 1; return; }

	if (setsockopt(s, 0, LOCAL_CAPMODE_SERVER, &one, sizeof(one)) != 0) {
		*result = 2; return;
	}

	/* Attempt to clear — must fail with ENOTCAPABLE */
	if (setsockopt(s, 0, LOCAL_CAPMODE_SERVER, &zero, sizeof(zero)) == 0) {
		*result = 3; return;
	}
	if (errno != ENOTCAPABLE) { *result = 4; return; }

	/* Setting it again (idempotent) must succeed */
	if (setsockopt(s, 0, LOCAL_CAPMODE_SERVER, &one, sizeof(one)) != 0) {
		*result = 5; return;
	}

	close(s);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(capmode_server_monotonic);
ATF_TC_BODY(capmode_server_monotonic, tc)
{
	int r;

	r = in_child(capmode_server_monotonic_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "LOCAL_CAPMODE_SERVER must be monotonic (result=%d)", r);
}

/* ---- sockcred2 sc_capmode tests ---- */

/*
 * Extended sockcred2 with sc_capmode field.  Defined locally so the
 * test compiles against older system headers that lack the field.
 */
struct sockcred2_ext {
	int	sc_version;
	pid_t	sc_pid;
	uid_t	sc_uid;
	uid_t	sc_euid;
	gid_t	sc_gid;
	gid_t	sc_egid;
	uint8_t	sc_capmode;
	uint8_t	sc_pad0[3];
	int	sc_ngroups;
	gid_t	sc_groups[1];
};

/*
 * sockcred2_capmode:
 * A child in cap mode sends a message on a socketpair with
 * LOCAL_CREDS_PERSISTENT enabled.  Parent receives SCM_CREDS2 and
 * verifies sc_capmode == 1.
 */
static void
sockcred2_capmode_body(int *result)
{
	int sv[2], one = 1;
	pid_t pid;
	int status;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}

	/* Enable LOCAL_CREDS_PERSISTENT on the receiving end */
	if (setsockopt(sv[0], 0, LOCAL_CREDS_PERSISTENT,
	    &one, sizeof(one)) != 0) {
		*result = 2; return;
	}

	pid = fork();
	if (pid < 0) { *result = 3; return; }
	if (pid == 0) {
		/* Child: enter cap mode, send a message */
		close(sv[0]);
		if (cap_enter() != 0) _exit(10);
		if (write(sv[1], "x", 1) != 1) _exit(11);
		close(sv[1]);
		_exit(0);
	}

	/* Parent: receive and check SCM_CREDS2 */
	close(sv[1]);

	if (waitpid(pid, &status, 0) != pid) { *result = 4; return; }
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		*result = 20 + WEXITSTATUS(status); return;
	}

	{
		struct msghdr msg;
		struct iovec iov;
		char buf[1];
		union {
			struct cmsghdr hdr;
			char control[CMSG_SPACE(SOCKCRED2SIZE(CMGROUP_MAX))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		struct sockcred2_ext *sc;

		memset(&msg, 0, sizeof(msg));
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf.control;
		msg.msg_controllen = sizeof(cmsgbuf.control);

		if (recvmsg(sv[0], &msg, 0) < 0) { *result = 5; return; }

		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL) { *result = 6; return; }
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_CREDS2) {
			*result = 7; return;
		}

		sc = (struct sockcred2_ext *)(void *)CMSG_DATA(cmsg);
		if (sc->sc_capmode != 1) { *result = 8; return; }
	}

	close(sv[0]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(sockcred2_capmode);
ATF_TC_BODY(sockcred2_capmode, tc)
{
	int r;

	r = in_child(sockcred2_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "sc_capmode must be 1 for cap-mode sender (result=%d)", r);
}

/*
 * sockcred2_no_capmode:
 * A child NOT in cap mode sends a message.  Verify sc_capmode == 0.
 */
static void
sockcred2_no_capmode_body(int *result)
{
	int sv[2], one = 1;
	pid_t pid;
	int status;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}

	if (setsockopt(sv[0], 0, LOCAL_CREDS_PERSISTENT,
	    &one, sizeof(one)) != 0) {
		*result = 2; return;
	}

	pid = fork();
	if (pid < 0) { *result = 3; return; }
	if (pid == 0) {
		/* Child: do NOT enter cap mode, just send */
		close(sv[0]);
		if (write(sv[1], "x", 1) != 1) _exit(11);
		close(sv[1]);
		_exit(0);
	}

	close(sv[1]);

	if (waitpid(pid, &status, 0) != pid) { *result = 4; return; }
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		*result = 20 + WEXITSTATUS(status); return;
	}

	{
		struct msghdr msg;
		struct iovec iov;
		char buf[1];
		union {
			struct cmsghdr hdr;
			char control[CMSG_SPACE(SOCKCRED2SIZE(CMGROUP_MAX))];
		} cmsgbuf;
		struct cmsghdr *cmsg;
		struct sockcred2_ext *sc;

		memset(&msg, 0, sizeof(msg));
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf.control;
		msg.msg_controllen = sizeof(cmsgbuf.control);

		if (recvmsg(sv[0], &msg, 0) < 0) { *result = 5; return; }

		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL) { *result = 6; return; }
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_CREDS2) {
			*result = 7; return;
		}

		sc = (struct sockcred2_ext *)(void *)CMSG_DATA(cmsg);
		if (sc->sc_capmode != 0) { *result = 8; return; }
	}

	close(sv[0]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(sockcred2_no_capmode);
ATF_TC_BODY(sockcred2_no_capmode, tc)
{
	int r;

	r = in_child(sockcred2_no_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "sc_capmode must be 0 for non-cap-mode sender (result=%d)", r);
}

/* ---- M2: capmode_server_allowed ---- */

/*
 * capmode_server_allowed:
 * Fork a child that opens a temp directory, enters cap mode, creates
 * a socket, binds via bindat(dirfd, ..., "sock"), listens, and writes
 * a sync byte.  Parent sets LOCAL_CAPMODE_SERVER on a client socket
 * and connects to the full path.  Verify connection succeeds (server
 * is in cap mode so LOCAL_CAPMODE_SERVER is satisfied).
 */
static void
capmode_server_allowed_body(int *result)
{
	struct sockaddr_un sun;
	char dir[] = "/tmp/cap_pure_test.XXXXXX";
	int cs, pv[2], one = 1;
	pid_t pid;
	int status;

	if (mkdtemp(dir) == NULL) { *result = 1; return; }
	if (pipe(pv) != 0) { *result = 2; return; }

	pid = fork();
	if (pid < 0) { *result = 3; return; }
	if (pid == 0) {
		/* Child: open dirfd, enter cap mode, bind+listen */
		struct sockaddr_un csun;
		int dfd, ls;

		close(pv[0]);

		dfd = open(dir, O_DIRECTORY | O_RDONLY);
		if (dfd < 0) _exit(10);

		if (cap_enter() != 0) _exit(11);

		ls = socket(AF_UNIX, SOCK_STREAM, 0);
		if (ls < 0) _exit(12);

		memset(&csun, 0, sizeof(csun));
		csun.sun_family = AF_UNIX;
		csun.sun_len = sizeof(csun);
		strlcpy(csun.sun_path, "sock", sizeof(csun.sun_path));

		if (bindat(dfd, ls, (struct sockaddr *)&csun,
		    sizeof(csun)) != 0)
			_exit(13);
		if (listen(ls, 1) != 0) _exit(14);

		/* Signal parent that we are ready */
		if (write(pv[1], "R", 1) != 1) _exit(15);

		/* Accept and immediately close */
		{
			int as = accept(ls, NULL, NULL);
			if (as < 0) _exit(16);
			close(as);
		}

		close(ls);
		close(dfd);
		close(pv[1]);
		_exit(0);
	}

	/* Parent: wait for child to be ready, then connect */
	close(pv[1]);
	{
		char byte;
		if (read(pv[0], &byte, 1) != 1 || byte != 'R') {
			*result = 4;
			(void)kill(pid, SIGKILL);
			(void)waitpid(pid, NULL, 0);
			close(pv[0]);
			return;
		}
	}
	close(pv[0]);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/sock", dir);

	cs = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cs < 0) { *result = 5; goto wait; }

	if (setsockopt(cs, 0, LOCAL_CAPMODE_SERVER, &one, sizeof(one)) != 0) {
		*result = 6; goto wait;
	}

	if (connect(cs, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		*result = 7; goto wait;
	}

	close(cs);
	*result = 0;

wait:
	if (waitpid(pid, &status, 0) != pid) { *result = 8; return; }
	if (*result == 0 &&
	    (!WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
		*result = 20 + WEXITSTATUS(status);
	}
	(void)unlink(sun.sun_path);
	(void)rmdir(dir);
}

ATF_TC_WITHOUT_HEAD(capmode_server_allowed);
ATF_TC_BODY(capmode_server_allowed, tc)
{
	int r;

	r = in_child(capmode_server_allowed_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "connect to cap-mode server with LOCAL_CAPMODE_SERVER "
	    "must succeed (result=%d)", r);
}

/* ---- M4: note_capmode_no_double_fire ---- */

/*
 * note_capmode_no_double_fire:
 * pdfork a child.  Child enters cap mode (fires NOTE_CAPMODE), parent
 * consumes the event, then child calls cap_enter() again (should be
 * a no-op).  Parent waits with a short timeout — should get 0 events
 * (no double fire).
 */
static void
note_capmode_no_double_fire_body(int *result)
{
	int pdfd, kq, pv[2], pv2[2];
	struct kevent kev;
	struct timespec ts;
	pid_t pid;
	char byte;
	int nev;

	if (pipe(pv) != 0) { *result = 1; return; }
	if (pipe(pv2) != 0) { *result = 2; return; }

	pid = pdfork(&pdfd, 0);
	if (pid < 0) { *result = 3; return; }
	if (pid == 0) {
		close(pv[1]);
		close(pv2[0]);

		/* Wait for parent to register kevent */
		if (read(pv[0], &byte, 1) != 1) _exit(1);
		close(pv[0]);

		/* First cap_enter — fires NOTE_CAPMODE */
		if (cap_enter() != 0) _exit(2);

		/* Signal parent that first cap_enter is done */
		if (write(pv2[1], "1", 1) != 1) _exit(3);

		/* Wait for parent to consume first event */
		/* Use a small delay to give parent time */
		usleep(200000);

		/* Second cap_enter — should be a no-op */
		(void)cap_enter();

		/* Signal parent that second cap_enter is done */
		if (write(pv2[1], "2", 1) != 1) _exit(4);

		sleep(5);
		_exit(0);
	}

	close(pv[0]);
	close(pv2[1]);

	kq = kqueue();
	if (kq < 0) { *result = 4; goto kill; }

	EV_SET(&kev, pdfd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
	    NOTE_CAPMODE, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0) { *result = 5; goto kill; }

	/* Signal child to proceed */
	write(pv[1], "x", 1);
	close(pv[1]);

	/* Wait for child to have done first cap_enter */
	if (read(pv2[0], &byte, 1) != 1 || byte != '1') {
		*result = 6; goto kill;
	}

	/* Consume the first NOTE_CAPMODE event */
	ts.tv_sec = 5;
	ts.tv_nsec = 0;
	nev = kevent(kq, NULL, 0, &kev, 1, &ts);
	if (nev != 1) { *result = 7; goto kill; }
	if ((kev.fflags & NOTE_CAPMODE) == 0) { *result = 8; goto kill; }

	/* Wait for child to have done second cap_enter */
	if (read(pv2[0], &byte, 1) != 1 || byte != '2') {
		*result = 9; goto kill;
	}

	/* Now wait with a short timeout — should get 0 events (no double fire) */
	ts.tv_sec = 0;
	ts.tv_nsec = 200000000;	/* 200ms */
	nev = kevent(kq, NULL, 0, &kev, 1, &ts);
	if (nev != 0) { *result = 10; goto kill; }

	close(kq);
	close(pv2[0]);
	pdkill(pdfd, SIGKILL);
	close(pdfd);
	*result = 0;
	return;

kill:
	close(pv2[0]);
	pdkill(pdfd, SIGKILL);
	close(pdfd);
}

ATF_TC_WITHOUT_HEAD(note_capmode_no_double_fire);
ATF_TC_BODY(note_capmode_no_double_fire, tc)
{
	int r;

	r = in_child(note_capmode_no_double_fire_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "NOTE_CAPMODE must not fire twice (result=%d)", r);
}

/* ---- NOTE_JAILED kevent test ---- */

/*
 * note_jailed_kevent:
 * pdfork a child, register EVFILT_PROCDESC with NOTE_JAILED on the
 * procdesc fd.  Child creates a jail and attaches to it.
 * Parent verifies the event fires with NOTE_JAILED in fflags.
 * Requires root (jail_set needs privilege).
 */
static void
note_jailed_kevent_body(int *result)
{
	int pdfd, kq, pv[2];
	struct kevent kev;
	struct timespec ts;
	pid_t pid;
	char byte;

	if (getuid() != 0) {
		/* Can't create jails without root */
		*result = 77;	/* sentinel: skip */
		return;
	}

	if (pipe(pv) != 0) { *result = 1; return; }

	pid = pdfork(&pdfd, 0);
	if (pid < 0) { *result = 2; return; }
	if (pid == 0) {
		struct jail j;

		close(pv[1]);
		/* Wait for parent to register kevent */
		if (read(pv[0], &byte, 1) != 1) _exit(1);
		close(pv[0]);

		/* Create and attach to a jail */
		memset(&j, 0, sizeof(j));
		j.version = JAIL_API_VERSION;
		j.path = __DECONST(char *, "/");
		j.hostname = __DECONST(char *, "captest");
		j.jailname = __DECONST(char *, "captest_note_jailed");
		if (jail(&j) < 0) _exit(2);

		sleep(60);
		_exit(0);
	}

	close(pv[0]);

	kq = kqueue();
	if (kq < 0) { *result = 3; return; }

	EV_SET(&kev, pdfd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
	    NOTE_JAILED, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0) { *result = 4; return; }

	/* Signal child */
	write(pv[1], "x", 1);
	close(pv[1]);

	/* Wait for NOTE_JAILED */
	ts.tv_sec = 5;
	ts.tv_nsec = 0;
	if (kevent(kq, NULL, 0, &kev, 1, &ts) != 1) { *result = 5; return; }

	if (kev.filter != EVFILT_PROCDESC) { *result = 6; return; }
	if ((kev.fflags & NOTE_JAILED) == 0) { *result = 7; return; }

	close(kq);
	pdkill(pdfd, SIGKILL);
	close(pdfd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(note_jailed_kevent);
ATF_TC_BODY(note_jailed_kevent, tc)
{
	int r;

	r = in_child(note_jailed_kevent_body, NULL);
	if (r == 77)
		atf_tc_skip("requires root for jail creation");
	ATF_REQUIRE_MSG(r == 0,
	    "NOTE_JAILED kevent must fire on jail attach (result=%d)", r);
}

/* ---- NOTE_SETUID kevent test ---- */

/*
 * note_setuid_kevent:
 * pdfork a child, register EVFILT_PROCDESC with NOTE_SETUID on the
 * procdesc fd.  Child calls setgid(getgid()) which always succeeds
 * and fires NOTE_SETUID (proc_set_cred is called regardless of
 * whether the value actually changed).
 * Parent verifies the event fires with NOTE_SETUID in fflags.
 */
static void
note_setuid_kevent_body(int *result)
{
	int pdfd, kq, pv[2];
	struct kevent kev;
	struct timespec ts;
	pid_t pid;
	char byte;

	if (pipe(pv) != 0) { *result = 1; return; }

	pid = pdfork(&pdfd, 0);
	if (pid < 0) { *result = 2; return; }
	if (pid == 0) {
		close(pv[1]);
		/* Wait for parent to register kevent */
		if (read(pv[0], &byte, 1) != 1) _exit(1);
		close(pv[0]);

		/* setgid to own gid -- always succeeds, fires NOTE_SETUID */
		if (setgid(getgid()) != 0) _exit(2);

		sleep(60);
		_exit(0);
	}

	close(pv[0]);

	kq = kqueue();
	if (kq < 0) { *result = 3; return; }

	EV_SET(&kev, pdfd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
	    NOTE_SETUID, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0) { *result = 4; return; }

	/* Signal child */
	write(pv[1], "x", 1);
	close(pv[1]);

	/* Wait for NOTE_SETUID */
	ts.tv_sec = 5;
	ts.tv_nsec = 0;
	if (kevent(kq, NULL, 0, &kev, 1, &ts) != 1) { *result = 5; return; }

	if (kev.filter != EVFILT_PROCDESC) { *result = 6; return; }
	if ((kev.fflags & NOTE_SETUID) == 0) { *result = 7; return; }

	close(kq);
	pdkill(pdfd, SIGKILL);
	close(pdfd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(note_setuid_kevent);
ATF_TC_BODY(note_setuid_kevent, tc)
{
	int r;

	r = in_child(note_setuid_kevent_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "NOTE_SETUID kevent must fire on credential change (result=%d)", r);
}

/* ---- NOTE_CHROOT kevent test ---- */

/*
 * note_chroot_kevent:
 * pdfork a child, register EVFILT_PROCDESC with NOTE_CHROOT on the
 * procdesc fd.  Child calls chroot("/") (always succeeds for root).
 * Parent verifies the event fires with NOTE_CHROOT in fflags.
 * Requires root -- chroot needs privilege.
 */
static void
note_chroot_kevent_body(int *result)
{
	int pdfd, kq, pv[2];
	struct kevent kev;
	struct timespec ts;
	pid_t pid;
	char byte;

	if (getuid() != 0) {
		/* chroot needs root */
		*result = 77;	/* sentinel: skip */
		return;
	}

	if (pipe(pv) != 0) { *result = 1; return; }

	pid = pdfork(&pdfd, 0);
	if (pid < 0) { *result = 2; return; }
	if (pid == 0) {
		close(pv[1]);
		/* Wait for parent to register kevent */
		if (read(pv[0], &byte, 1) != 1) _exit(1);
		close(pv[0]);

		/* chroot to / -- always succeeds for root */
		if (chroot("/") != 0) _exit(2);

		sleep(60);
		_exit(0);
	}

	close(pv[0]);

	kq = kqueue();
	if (kq < 0) { *result = 3; return; }

	EV_SET(&kev, pdfd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
	    NOTE_CHROOT, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0) { *result = 4; return; }

	/* Signal child */
	write(pv[1], "x", 1);
	close(pv[1]);

	/* Wait for NOTE_CHROOT */
	ts.tv_sec = 5;
	ts.tv_nsec = 0;
	if (kevent(kq, NULL, 0, &kev, 1, &ts) != 1) { *result = 5; return; }

	if (kev.filter != EVFILT_PROCDESC) { *result = 6; return; }
	if ((kev.fflags & NOTE_CHROOT) == 0) { *result = 7; return; }

	close(kq);
	pdkill(pdfd, SIGKILL);
	close(pdfd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(note_chroot_kevent);
ATF_TC_BODY(note_chroot_kevent, tc)
{
	int r;

	r = in_child(note_chroot_kevent_body, NULL);
	if (r == 77)
		atf_tc_skip("requires root for chroot");
	ATF_REQUIRE_MSG(r == 0,
	    "NOTE_CHROOT kevent must fire on chroot (result=%d)", r);
}

/* ---- M5: capmode_connect_seqpacket ---- */

/*
 * capmode_connect_seqpacket:
 * Same as capmode_connect_denied but with SOCK_SEQPACKET.
 * Set LOCAL_CAP_CONNECT on a listening SEQPACKET socket.
 * A non-cap-mode connect must fail with ENOTCAPABLE.
 */
static void
capmode_connect_seqpacket_body(int *result)
{
	struct sockaddr_un sun;
	char dir[] = "/tmp/cap_pure_test.XXXXXX";
	char path[128];
	int ls, cs, one = 1;

	if (mkdtemp(dir) == NULL) { *result = 1; return; }
	snprintf(path, sizeof(path), "%s/sock", dir);

	ls = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (ls < 0) { *result = 2; return; }

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (bind(ls, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		*result = 3; return;
	}
	if (setsockopt(ls, 0, LOCAL_CAP_CONNECT, &one, sizeof(one)) != 0) {
		*result = 4; return;
	}
	if (listen(ls, 1) != 0) { *result = 5; return; }

	/* We are NOT in cap mode — connect must fail with ENOTCAPABLE */
	cs = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (cs < 0) { *result = 6; return; }
	if (connect(cs, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
		*result = 7; return;
	}
	if (errno != ENOTCAPABLE) { *result = 8; return; }

	close(cs);
	close(ls);
	(void)unlink(path);
	(void)rmdir(dir);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(capmode_connect_seqpacket);
ATF_TC_BODY(capmode_connect_seqpacket, tc)
{
	int r;

	r = in_child(capmode_connect_seqpacket_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "SEQPACKET non-cap-mode connect must fail with "
	    "ENOTCAPABLE (result=%d)", r);
}

/* ---- M6: mmap_capmode_idempotent ---- */

/*
 * mmap_capmode_idempotent:
 * shm_open, call cap_mmap_capmode twice. Both must succeed.
 */
static void
mmap_capmode_idempotent_body(int *result)
{
	int fd;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	if (fd < 0) { *result = 1; return; }
	if (ftruncate(fd, 4096) != 0) { *result = 2; return; }

	if (syscall(SYS_cap_mmap_capmode, fd) != 0) { *result = 3; return; }
	if (syscall(SYS_cap_mmap_capmode, fd) != 0) { *result = 4; return; }

	close(fd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(mmap_capmode_idempotent);
ATF_TC_BODY(mmap_capmode_idempotent, tc)
{
	int r;

	r = in_child(mmap_capmode_idempotent_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_mmap_capmode must be idempotent (result=%d)", r);
}

/* ---- M7: lookup_capmode_idempotent ---- */

/*
 * lookup_capmode_idempotent:
 * open("."), call cap_lookup_capmode twice. Both must succeed.
 */
static void
lookup_capmode_idempotent_body(int *result)
{
	int dirfd;

	dirfd = open(".", O_DIRECTORY | O_RDONLY);
	if (dirfd < 0) { *result = 1; return; }

	if (syscall(SYS_cap_lookup_capmode, dirfd) != 0) {
		*result = 2; return;
	}
	if (syscall(SYS_cap_lookup_capmode, dirfd) != 0) {
		*result = 3; return;
	}

	close(dirfd);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(lookup_capmode_idempotent);
ATF_TC_BODY(lookup_capmode_idempotent, tc)
{
	int r;

	r = in_child(lookup_capmode_idempotent_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "cap_lookup_capmode must be idempotent (result=%d)", r);
}

/* ---- CAP_SUFFICIENT tests ---- */

/*
 * cap_sufficient_fchmod:
 * Open a temp file, cap_ambient_limit(fd), cap_enter(), fchmod()
 * should succeed.  Verify mode changed.
 */
static void
cap_sufficient_fchmod_body(int *result)
{
	struct stat sb;
	int fd;

	fd = open("/tmp/cap_suf_fchmod", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }

	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 2; return; }
	if (cap_enter() != 0) { *result = 3; return; }

	if (fchmod(fd, 0600) != 0) { *result = 4; return; }

	if (fstat(fd, &sb) != 0) { *result = 5; return; }
	if ((sb.st_mode & 0777) != 0600) { *result = 6; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_sufficient_fchmod);
ATF_TC_BODY(cap_sufficient_fchmod, tc)
{
	int r;

	r = in_child(cap_sufficient_fchmod_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "CAP_SUFFICIENT fchmod in cap mode (result=%d)", r);
	unlink("/tmp/cap_suf_fchmod");
}

/*
 * cap_sufficient_fchown:
 * Open a temp file, cap_ambient_limit(fd), cap_enter(), fchown()
 * should succeed.
 */
static void
cap_sufficient_fchown_body(int *result)
{
	int fd;

	fd = open("/tmp/cap_suf_fchown", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }

	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 2; return; }
	if (cap_enter() != 0) { *result = 3; return; }

	/* fchown to own uid/gid -- always succeeds */
	if (fchown(fd, getuid(), getgid()) != 0) { *result = 4; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_sufficient_fchown);
ATF_TC_BODY(cap_sufficient_fchown, tc)
{
	int r;

	r = in_child(cap_sufficient_fchown_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "CAP_SUFFICIENT fchown in cap mode (result=%d)", r);
	unlink("/tmp/cap_suf_fchown");
}

/*
 * cap_sufficient_write:
 * Open a file, cap_ambient_limit(fd), cap_enter(), write()
 * should succeed.
 */
static void
cap_sufficient_write_body(int *result)
{
	int fd;

	fd = open("/tmp/cap_suf_write", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }

	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 2; return; }
	if (cap_enter() != 0) { *result = 3; return; }

	if (write(fd, "hello", 5) != 5) { *result = 4; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_sufficient_write);
ATF_TC_BODY(cap_sufficient_write, tc)
{
	int r;

	r = in_child(cap_sufficient_write_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "CAP_SUFFICIENT write in cap mode (result=%d)", r);
	unlink("/tmp/cap_suf_write");
}

/*
 * cap_sufficient_socket_ops:
 * cap_ambient_limit() on socketpair fds, cap_enter(), send/recv should succeed.
 */
static void
cap_sufficient_socket_ops_body(int *result)
{
	int sv[2];
	char buf[4];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*result = 1; return;
	}

	if (syscall(SYS_cap_ambient_limit, sv[0]) != 0) { *result = 2; return; }
	if (syscall(SYS_cap_ambient_limit, sv[1]) != 0) { *result = 3; return; }
	if (cap_enter() != 0) { *result = 4; return; }

	if (send(sv[0], "test", 4, 0) != 4) { *result = 5; return; }
	if (recv(sv[1], buf, 4, 0) != 4) { *result = 6; return; }
	if (memcmp(buf, "test", 4) != 0) { *result = 7; return; }

	close(sv[0]);
	close(sv[1]);
	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_sufficient_socket_ops);
ATF_TC_BODY(cap_sufficient_socket_ops, tc)
{
	int r;

	r = in_child(cap_sufficient_socket_ops_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "CAP_SUFFICIENT socket send/recv in cap mode (result=%d)", r);
}

/*
 * cap_sufficient_not_in_capmode:
 * cap_ambient_limit(fd) but do NOT cap_enter().  fchmod() should
 * still work normally (CAP_SUFFICIENT only skips checks in capmode,
 * and normal fchmod works outside capmode anyway -- verifies no
 * regression).
 */
static void
cap_sufficient_not_in_capmode_body(int *result)
{
	struct stat sb;
	int fd;

	fd = open("/tmp/cap_suf_nocap", O_RDWR | O_CREAT, 0644);
	if (fd < 0) { *result = 1; return; }

	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 2; return; }

	/* NOT entering cap mode -- fchmod should still work */
	if (fchmod(fd, 0600) != 0) { *result = 3; return; }

	if (fstat(fd, &sb) != 0) { *result = 4; return; }
	if ((sb.st_mode & 0777) != 0600) { *result = 5; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_sufficient_not_in_capmode);
ATF_TC_BODY(cap_sufficient_not_in_capmode, tc)
{
	int r;

	r = in_child(cap_sufficient_not_in_capmode_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "CAP_SUFFICIENT outside cap mode: no regression (result=%d)", r);
	unlink("/tmp/cap_suf_nocap");
}

/*
 * cap_sufficient_ioctl:
 * Open /dev/null, cap_ambient_limit(fd), cap_enter(),
 * ioctl(FIONREAD) should succeed.
 */
static void
cap_sufficient_ioctl_body(int *result)
{
	int fd, nb;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) { *result = 1; return; }

	if (syscall(SYS_cap_ambient_limit, fd) != 0) { *result = 2; return; }
	if (cap_enter() != 0) { *result = 3; return; }

	nb = 0;
	if (ioctl(fd, FIONBIO, &nb) != 0) { *result = 4; return; }

	*result = 0;
}

ATF_TC_WITHOUT_HEAD(cap_sufficient_ioctl);
ATF_TC_BODY(cap_sufficient_ioctl, tc)
{
	int r;

	r = in_child(cap_sufficient_ioctl_body, NULL);
	ATF_REQUIRE_MSG(r == 0,
	    "CAP_SUFFICIENT ioctl in cap mode (result=%d)", r);
}

/* ---- ATF test program ---- */

ATF_TP_ADD_TCS(tp)
{

	/* cap_ambient_limit */
	ATF_TP_ADD_TC(tp, ambient_limit_outside_capmode);
	ATF_TP_ADD_TC(tp, ambient_limit_inside_capmode);
	ATF_TP_ADD_TC(tp, ambient_limit_bad_fd);
	ATF_TP_ADD_TC(tp, ambient_limit_monotonic);
	ATF_TP_ADD_TC(tp, ambient_limit_dup);
	ATF_TP_ADD_TC(tp, ambient_limit_socket);
	ATF_TP_ADD_TC(tp, ambient_limit_pipe);

	/* SCM_RIGHTS */
	ATF_TP_ADD_TC(tp, scm_rights_noncap);
	ATF_TP_ADD_TC(tp, scm_rights_cap);

	/* Fork */
	ATF_TP_ADD_TC(tp, fork_inherit);

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

	/* pdincapmode */
	ATF_TP_ADD_TC(tp, pdincapmode_before_capenter);
	ATF_TP_ADD_TC(tp, pdincapmode_after_capenter);
	ATF_TP_ADD_TC(tp, pdincapmode_bad_fd);

	/* NOTE_CAPMODE kqueue event */
	ATF_TP_ADD_TC(tp, note_capmode_kevent);

	/* LOCAL_CAP_CONNECT */
	ATF_TP_ADD_TC(tp, capmode_connect_denied);
	ATF_TP_ADD_TC(tp, capmode_connect_allowed);
	ATF_TP_ADD_TC(tp, capmode_connect_monotonic);
	ATF_TP_ADD_TC(tp, capmode_connect_dgram);

	/* pdincapmode exited process */
	ATF_TP_ADD_TC(tp, pdincapmode_exited);

	/* cap_mmap_capmode */
	ATF_TP_ADD_TC(tp, mmap_capmode_denied);
	ATF_TP_ADD_TC(tp, mmap_capmode_allowed);
	ATF_TP_ADD_TC(tp, mmap_capmode_bad_fd);

	/* cap_lookup_capmode */
	ATF_TP_ADD_TC(tp, lookup_capmode_denied);
	ATF_TP_ADD_TC(tp, lookup_capmode_allowed);
	ATF_TP_ADD_TC(tp, lookup_capmode_bad_fd);
	ATF_TP_ADD_TC(tp, lookup_capmode_idempotent);

	/* LOCAL_CAP_CONNECT SEQPACKET */
	ATF_TP_ADD_TC(tp, capmode_connect_seqpacket);

	/* LOCAL_CAPMODE_SERVER */
	ATF_TP_ADD_TC(tp, capmode_server_denied);
	ATF_TP_ADD_TC(tp, capmode_server_allowed);
	ATF_TP_ADD_TC(tp, capmode_server_monotonic);

	/* LOCAL_CAP_REQ */
	ATF_TP_ADD_TC(tp, cap_req_send_denied);
	ATF_TP_ADD_TC(tp, cap_req_recv_denied);
	ATF_TP_ADD_TC(tp, cap_req_allowed);
	ATF_TP_ADD_TC(tp, cap_req_monotonic);
	ATF_TP_ADD_TC(tp, cap_req_dgram);

	/* NOTE_CAPMODE no double fire */
	ATF_TP_ADD_TC(tp, note_capmode_no_double_fire);

	/* NOTE_JAILED */
	ATF_TP_ADD_TC(tp, note_jailed_kevent);

	/* NOTE_SETUID */
	ATF_TP_ADD_TC(tp, note_setuid_kevent);

	/* NOTE_CHROOT */
	ATF_TP_ADD_TC(tp, note_chroot_kevent);

	/* cap_mmap_capmode idempotent */
	ATF_TP_ADD_TC(tp, mmap_capmode_idempotent);

	/* sockcred2 sc_capmode */
	ATF_TP_ADD_TC(tp, sockcred2_capmode);
	ATF_TP_ADD_TC(tp, sockcred2_no_capmode);

	/* CAP_SUFFICIENT */
	ATF_TP_ADD_TC(tp, cap_sufficient_fchmod);
	ATF_TP_ADD_TC(tp, cap_sufficient_fchown);
	ATF_TP_ADD_TC(tp, cap_sufficient_write);
	ATF_TP_ADD_TC(tp, cap_sufficient_socket_ops);
	ATF_TP_ADD_TC(tp, cap_sufficient_not_in_capmode);
	ATF_TP_ADD_TC(tp, cap_sufficient_ioctl);

	return (atf_no_error());
}
