/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Tests for cap_cloexec_limit(2) and cap_clofork_limit(2).
 *
 * These are monotonic descriptor confinement locks that operate
 * independently of the POSIX FD_CLOEXEC and FD_CLOFORK flags.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/* Constants if not yet in installed headers. */
#ifndef CAP_CLOEXEC_UNLOCKED
#define	CAP_CLOEXEC_UNLOCKED	0
#define	CAP_CLOEXEC_LOCKED	1
#endif
#ifndef CAP_CLOEXEC_ONCE
#define	CAP_CLOEXEC_ONCE	2
#endif
#ifndef CAP_CLOFORK_UNLOCKED
#define	CAP_CLOFORK_UNLOCKED	0
#define	CAP_CLOFORK_LOCKED	1
#endif
#ifndef CAP_CLOFORK_ONCE
#define	CAP_CLOFORK_ONCE	2
#endif
#ifndef CAP_XFER_UNLIMITED
#define	CAP_XFER_UNLIMITED	0
#define	CAP_XFER_NONE		2
#endif

/* Helpers for exec test — child checks if fd is open or closed. */
static char *exec_helper_path;

static void
build_exec_helper(const atf_tc_t *tc)
{
	FILE *f;

	f = fopen("cloexec_helper.c", "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f,
	    "#include <errno.h>\n"
	    "#include <fcntl.h>\n"
	    "#include <stdlib.h>\n"
	    "#include <string.h>\n"
	    "#include <unistd.h>\n"
	    "int main(int argc, char **argv) {\n"
	    "    int fd = atoi(argv[1]);\n"
	    "    int closed = fcntl(fd, F_GETFD) == -1 && errno == EBADF;\n"
	    "    if (argc == 3 && strcmp(argv[2], \"once\") == 0) {\n"
	    "        if (closed)\n"
	    "            return (10);\n"
	    "        execl(argv[0], argv[0], argv[1], \"locked\", NULL);\n"
	    "        return (11);\n"
	    "    }\n"
	    "    if (argc == 3 && strcmp(argv[2], \"locked\") == 0)\n"
	    "        return (closed ? 0 : 12);\n"
	    "    if (closed)\n"
	    "        return (0);\n"	/* closed — lock worked */
	    "    return (1);\n"		/* still open — lock didn't work */
	    "}\n");
	fclose(f);
	ATF_REQUIRE(system("cc -o cloexec_helper cloexec_helper.c") == 0);
	exec_helper_path = strdup("./cloexec_helper");
}

static void
send_fd(int sock, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	char control[CMSG_SPACE(sizeof(fd))];
	struct cmsghdr *cm;
	char byte = '\0';

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_len = CMSG_LEN(sizeof(fd));
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cm), &fd, sizeof(fd));
	ATF_REQUIRE(sendmsg(sock, &msg, 0) == sizeof(byte));
}

static int
recv_fd(int sock)
{
	struct msghdr msg;
	struct iovec iov;
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cm;
	char byte;
	int fd;

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	ATF_REQUIRE(recvmsg(sock, &msg, 0) == sizeof(byte));
	cm = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cm != NULL);
	ATF_REQUIRE(cm->cmsg_level == SOL_SOCKET);
	ATF_REQUIRE(cm->cmsg_type == SCM_RIGHTS);
	memcpy(&fd, CMSG_DATA(cm), sizeof(fd));
	return (fd);
}

struct fork_once_arg {
	pthread_barrier_t	*barrier;
	int			 fd;
	int			 error;
	int			 inherited;
};

static void *
fork_once_worker(void *cookie)
{
	struct fork_once_arg *arg;
	int barrier_error, status;
	pid_t pid;

	arg = cookie;
	barrier_error = pthread_barrier_wait(arg->barrier);
	if (barrier_error != 0 &&
	    barrier_error != PTHREAD_BARRIER_SERIAL_THREAD) {
		arg->error = barrier_error;
		return (NULL);
	}

	pid = fork();
	if (pid == -1) {
		arg->error = errno;
		return (NULL);
	}
	if (pid == 0)
		_exit(fcntl(arg->fd, F_GETFD) == -1 && errno == EBADF ? 0 : 1);
	if (waitpid(pid, &status, 0) != pid) {
		arg->error = errno;
		return (NULL);
	}
	if (!WIFEXITED(status) ||
	    (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 1)) {
		arg->error = ECHILD;
		return (NULL);
	}
	arg->inherited = WEXITSTATUS(status);
	return (NULL);
}

/* ---- cap_cloexec_limit syscall tests ---- */

ATF_TC_WITHOUT_HEAD(cloexec_limit_default);
ATF_TC_BODY(cloexec_limit_default, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* Default is UNLOCKED — locking should succeed. */
	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(cloexec_limit_widen_fails);
ATF_TC_BODY(cloexec_limit_widen_fails, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);

	/* Widening back to UNLOCKED must fail. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(fd, CAP_CLOEXEC_UNLOCKED) == -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(cloexec_once_monotonic);
ATF_TC_BODY(cloexec_once_monotonic, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(fd, CAP_CLOEXEC_UNLOCKED) == -1);

	/* ONCE can still be tightened immediately to LOCKED. */
	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(cloexec_limit_bad_fd);
ATF_TC_BODY(cloexec_limit_bad_fd, tc)
{

	ATF_REQUIRE_ERRNO(EBADF,
	    cap_cloexec_limit(999, CAP_CLOEXEC_LOCKED) == -1);
}

ATF_TC_WITHOUT_HEAD(cloexec_limit_bad_state);
ATF_TC_BODY(cloexec_limit_bad_state, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE_ERRNO(EINVAL, cap_cloexec_limit(fd, -1) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, cap_cloexec_limit(fd, 3) == -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(cloexec_limit_same_is_ok);
ATF_TC_BODY(cloexec_limit_same_is_ok, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);
	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(cloexec_limit_dup_inherits);
ATF_TC_BODY(cloexec_limit_dup_inherits, tc)
{
	int fd, fd2;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);

	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);

	/* Dup'd descriptor should already be LOCKED — can't widen. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(fd2, CAP_CLOEXEC_UNLOCKED) == -1);

	close(fd);
	close(fd2);
}

/*
 * The critical test: lock overrides the POSIX flag.
 * Process clears FD_CLOEXEC via fcntl — that works (no error).
 * But exec still closes the fd because the lock is a separate layer.
 */
ATF_TC(cloexec_limit_overrides_flag);
ATF_TC_HEAD(cloexec_limit_overrides_flag, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Locked fd is closed on exec even if FD_CLOEXEC is cleared");
}
ATF_TC_BODY(cloexec_limit_overrides_flag, tc)
{
	char fdstr[16];
	int fd, status;
	pid_t pid;

	build_exec_helper(tc);

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* Lock it. */
	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);

	/* Clear the POSIX flag — this must succeed (no error). */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);

	/* Verify the flag is actually cleared. */
	ATF_CHECK_EQ(fcntl(fd, F_GETFD) & FD_CLOEXEC, 0);

	/* Exec — the lock should close it regardless. */
	snprintf(fdstr, sizeof(fdstr), "%d", fd);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(exec_helper_path, "cloexec_helper", fdstr, NULL);
		_exit(99);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "fd survived exec despite lock (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(fd);
}

ATF_TC(cloexec_once_survives_one);
ATF_TC_HEAD(cloexec_once_survives_one, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CAP_CLOEXEC_ONCE survives one exec and closes on the next");
}
ATF_TC_BODY(cloexec_once_survives_one, tc)
{
	char fdstr[16];
	int fd, status;
	pid_t pid;

	build_exec_helper(tc);

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == 0);

	snprintf(fdstr, sizeof(fdstr), "%d", fd);

	/*
	 * The one-shot state grants no exception to FD_CLOEXEC.  This exec
	 * must close the child's copy, without affecting the parent's state.
	 */
	ATF_REQUIRE(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(exec_helper_path, "cloexec_helper", fdstr, NULL);
		_exit(98);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "FD_CLOEXEC did not override exec-once (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	/*
	 * With FD_CLOEXEC clear, the parent's copy must survive exactly one
	 * exec and then close on the second.
	 */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(exec_helper_path, "cloexec_helper", fdstr, "once",
		    NULL);
		_exit(99);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "exec-once lifecycle failed (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(fd);
}

/*
 * Control test: without the lock, clearing FD_CLOEXEC lets fd survive exec.
 */
ATF_TC(cloexec_unlocked_flag_controls);
ATF_TC_HEAD(cloexec_unlocked_flag_controls, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Without lock, clearing FD_CLOEXEC lets fd survive exec");
}
ATF_TC_BODY(cloexec_unlocked_flag_controls, tc)
{
	char fdstr[16];
	int fd, status;
	pid_t pid;

	build_exec_helper(tc);

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* No lock. Clear CLOEXEC. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);

	snprintf(fdstr, sizeof(fdstr), "%d", fd);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(exec_helper_path, "cloexec_helper", fdstr, NULL);
		_exit(99);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	    "fd was unexpectedly closed on exec (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(cloexec_limit_f_setfd_unaffected);
ATF_TC_BODY(cloexec_limit_f_setfd_unaffected, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);

	/* F_SETFD clearing CLOEXEC must succeed — lock is invisible. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_CHECK_EQ(fcntl(fd, F_GETFD) & FD_CLOEXEC, 0);

	/* F_SETFD setting CLOEXEC must also succeed. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
	ATF_CHECK_EQ(fcntl(fd, F_GETFD) & FD_CLOEXEC, FD_CLOEXEC);

	close(fd);
}

/* ---- cap_clofork_limit syscall tests ---- */

ATF_TC_WITHOUT_HEAD(clofork_limit_default);
ATF_TC_BODY(clofork_limit_default, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == 0);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(clofork_limit_widen_fails);
ATF_TC_BODY(clofork_limit_widen_fails, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == 0);

	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(clofork_once_monotonic);
ATF_TC_BODY(clofork_once_monotonic, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1);

	/* ONCE can still be tightened immediately to LOCKED. */
	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(clofork_limit_bad_fd);
ATF_TC_BODY(clofork_limit_bad_fd, tc)
{

	ATF_REQUIRE_ERRNO(EBADF,
	    cap_clofork_limit(999, CAP_CLOFORK_LOCKED) == -1);
}

ATF_TC_WITHOUT_HEAD(clofork_limit_bad_state);
ATF_TC_BODY(clofork_limit_bad_state, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE_ERRNO(EINVAL, cap_clofork_limit(fd, -1) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, cap_clofork_limit(fd, 3) == -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(clofork_limit_dup_inherits);
ATF_TC_BODY(clofork_limit_dup_inherits, tc)
{
	int fd, fd2;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == 0);

	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);

	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(fd2, CAP_CLOFORK_UNLOCKED) == -1);

	close(fd);
	close(fd2);
}

/*
 * The critical test: lock prevents fork inheritance.
 * Process clears FD_CLOFORK — that works.
 * But fork still skips the fd because the lock overrides.
 */
ATF_TC(clofork_limit_overrides_flag);
ATF_TC_HEAD(clofork_limit_overrides_flag, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Locked fd is not inherited by fork even if FD_CLOFORK is cleared");
}
ATF_TC_BODY(clofork_limit_overrides_flag, tc)
{
	int fd, status;
	pid_t pid;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* Lock it. */
	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == 0);

	/* Clear the POSIX flag. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);

	/* Verify flag is cleared. */
	ATF_CHECK_EQ(fcntl(fd, F_GETFD) & FD_CLOFORK, 0);

	/* Fork — child should NOT have the fd. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (fcntl(fd, F_GETFD) == -1 && errno == EBADF)
			_exit(0);	/* closed — lock worked */
		_exit(1);		/* still open — lock failed */
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "fd was inherited by child despite lock (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	/* Parent should still have the fd. */
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);

	close(fd);
}

ATF_TC(clofork_once_inherits_one);
ATF_TC_HEAD(clofork_once_inherits_one, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CAP_CLOFORK_ONCE permits one child and locks both branches");
}
ATF_TC_BODY(clofork_once_inherits_one, tc)
{
	int fd, status;
	pid_t pid;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == 0);

	/*
	 * FD_CLOFORK still wins.  Because no propagation occurred, this
	 * omitted fork must not consume the one-shot state in the parent.
	 */
	ATF_REQUIRE(fcntl(fd, F_SETFD, FD_CLOFORK) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 9);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "FD_CLOFORK did not override fork-once (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	/* Clearing FD_CLOFORK now permits the single propagation. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int child_status;
		pid_t grandchild;

		/* The first child receives the descriptor. */
		if (fcntl(fd, F_GETFD) == -1)
			_exit(10);

		/* Its locked state prevents inheritance by a grandchild. */
		grandchild = fork();
		if (grandchild < 0)
			_exit(11);
		if (grandchild == 0)
			_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ?
			    0 : 12);
		if (waitpid(grandchild, &child_status, 0) != grandchild)
			_exit(13);
		if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
			_exit(14);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child-side fork-once lifecycle failed (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	/* The parent retains the fd, but a second child must not. */
	ATF_REQUIRE(fcntl(fd, F_GETFD) != -1);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 20);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "parent-side fork-once lifecycle failed (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(clofork_once_concurrent);
ATF_TC_BODY(clofork_once_concurrent, tc)
{
	struct fork_once_arg args[2];
	pthread_barrier_t barrier;
	pthread_t threads[2];
	int barrier_error, fd, i;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == 0);
	ATF_REQUIRE_EQ(pthread_barrier_init(&barrier, NULL, 3), 0);

	memset(args, 0, sizeof(args));
	for (i = 0; i < 2; i++) {
		args[i].barrier = &barrier;
		args[i].fd = fd;
		ATF_REQUIRE_EQ(pthread_create(&threads[i], NULL,
		    fork_once_worker, &args[i]), 0);
	}
	barrier_error = pthread_barrier_wait(&barrier);
	ATF_REQUIRE(barrier_error == 0 ||
	    barrier_error == PTHREAD_BARRIER_SERIAL_THREAD);
	for (i = 0; i < 2; i++)
		ATF_REQUIRE_EQ(pthread_join(threads[i], NULL), 0);
	ATF_REQUIRE_EQ(pthread_barrier_destroy(&barrier), 0);

	ATF_REQUIRE_EQ(args[0].error, 0);
	ATF_REQUIRE_EQ(args[1].error, 0);
	ATF_REQUIRE_MSG(args[0].inherited + args[1].inherited == 1,
	    "expected exactly one concurrent child to inherit: %d + %d",
	    args[0].inherited, args[1].inherited);

	close(fd);
}

/*
 * Control test: without lock, clearing FD_CLOFORK lets fd survive fork.
 */
ATF_TC(clofork_unlocked_flag_controls);
ATF_TC_HEAD(clofork_unlocked_flag_controls, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Without lock, clearing FD_CLOFORK lets fd survive fork");
}
ATF_TC_BODY(clofork_unlocked_flag_controls, tc)
{
	int fd, status;
	pid_t pid;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	/* No lock. Clear CLOFORK. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (fcntl(fd, F_GETFD) == -1 && errno == EBADF)
			_exit(1);	/* closed — wrong */
		_exit(0);		/* open — correct */
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "fd unexpectedly not inherited (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(clofork_limit_f_setfd_unaffected);
ATF_TC_BODY(clofork_limit_f_setfd_unaffected, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == 0);

	/* F_SETFD clearing CLOFORK must succeed. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_CHECK_EQ(fcntl(fd, F_GETFD) & FD_CLOFORK, 0);

	/* F_SETFD setting CLOFORK must also succeed. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, FD_CLOFORK) == 0);
	ATF_CHECK_EQ(fcntl(fd, F_GETFD) & FD_CLOFORK, FD_CLOFORK);

	close(fd);
}

ATF_TC_WITHOUT_HEAD(propagation_once_scm_rights);
ATF_TC_BODY(propagation_once_scm_rights, tc)
{
	char fdstr[16];
	int fd, recvfd, status, sv[2];
	pid_t pid;

	build_exec_helper(tc);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == 0);
	send_fd(sv[0], fd);
	recvfd = recv_fd(sv[1]);

	/* SCM_RIGHTS must preserve both intermediate states exactly. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(recvfd, CAP_CLOEXEC_UNLOCKED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(recvfd, CAP_CLOFORK_UNLOCKED) == -1);
	ATF_REQUIRE(cap_cloexec_limit(recvfd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(recvfd, CAP_CLOFORK_ONCE) == 0);

	/*
	 * Exercise both received states end to end.  The first fork inherits
	 * the descriptor and its child survives one exec, then loses it on
	 * the second exec.
	 */
	snprintf(fdstr, sizeof(fdstr), "%d", recvfd);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(exec_helper_path, "cloexec_helper", fdstr, "once", NULL);
		_exit(30);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "received descriptor did not enforce one-shot propagation "
	    "(exit %d)", WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	/* The first fork consumed the parent's fork allowance. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fcntl(recvfd, F_GETFD) == -1 && errno == EBADF ?
		    0 : 31);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "received descriptor survived a second fork (exit %d)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(recvfd);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(propagation_once_dup);
ATF_TC_BODY(propagation_once_dup, tc)
{
	int fd, fd2;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == 0);

	fd2 = dup(fd);
	ATF_REQUIRE(fd2 >= 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(fd2, CAP_CLOEXEC_UNLOCKED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(fd2, CAP_CLOFORK_UNLOCKED) == -1);
	ATF_REQUIRE(cap_cloexec_limit(fd2, CAP_CLOEXEC_ONCE) == 0);
	ATF_REQUIRE(cap_clofork_limit(fd2, CAP_CLOFORK_ONCE) == 0);

	close(fd2);
	close(fd);
}

/* ---- combined tests ---- */

ATF_TC(full_confinement);
ATF_TC_HEAD(full_confinement, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "All three confinement locks together");
}
ATF_TC_BODY(full_confinement, tc)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_xfer_limit(fd, CAP_XFER_NONE) == 0);
	ATF_REQUIRE(cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == 0);
	ATF_REQUIRE(cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == 0);

	/* All three locked — none can be widened. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_xfer_limit(fd, CAP_XFER_UNLIMITED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_cloexec_limit(fd, CAP_CLOEXEC_UNLOCKED) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1);

	/* F_SETFD still works — flags are independent. */
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_REQUIRE(fcntl(fd, F_SETFD, FD_CLOEXEC | FD_CLOFORK) == 0);

	close(fd);
}

/* ---- capability mode ---- */

ATF_TC_WITHOUT_HEAD(confinement_capmode);
ATF_TC_BODY(confinement_capmode, tc)
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
		if (cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) != 0)
			_exit(1);
		if (cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) != 0)
			_exit(2);
		/* Widening must fail. */
		if (cap_cloexec_limit(fd, CAP_CLOEXEC_UNLOCKED) == 0)
			_exit(3);
		if (errno != ENOTCAPABLE)
			_exit(4);
		if (cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == 0)
			_exit(5);
		if (errno != ENOTCAPABLE)
			_exit(6);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "cap mode test failed: exit %d",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(fd);
}

/* ---- test registration ---- */

ATF_TP_ADD_TCS(tp)
{

	/* cap_cloexec_limit */
	ATF_TP_ADD_TC(tp, cloexec_limit_default);
	ATF_TP_ADD_TC(tp, cloexec_limit_widen_fails);
	ATF_TP_ADD_TC(tp, cloexec_once_monotonic);
	ATF_TP_ADD_TC(tp, cloexec_limit_bad_fd);
	ATF_TP_ADD_TC(tp, cloexec_limit_bad_state);
	ATF_TP_ADD_TC(tp, cloexec_limit_same_is_ok);
	ATF_TP_ADD_TC(tp, cloexec_limit_dup_inherits);
	ATF_TP_ADD_TC(tp, cloexec_limit_overrides_flag);
	ATF_TP_ADD_TC(tp, cloexec_once_survives_one);
	ATF_TP_ADD_TC(tp, cloexec_unlocked_flag_controls);
	ATF_TP_ADD_TC(tp, cloexec_limit_f_setfd_unaffected);

	/* cap_clofork_limit */
	ATF_TP_ADD_TC(tp, clofork_limit_default);
	ATF_TP_ADD_TC(tp, clofork_limit_widen_fails);
	ATF_TP_ADD_TC(tp, clofork_once_monotonic);
	ATF_TP_ADD_TC(tp, clofork_limit_bad_fd);
	ATF_TP_ADD_TC(tp, clofork_limit_bad_state);
	ATF_TP_ADD_TC(tp, clofork_limit_dup_inherits);
	ATF_TP_ADD_TC(tp, clofork_limit_overrides_flag);
	ATF_TP_ADD_TC(tp, clofork_once_inherits_one);
	ATF_TP_ADD_TC(tp, clofork_once_concurrent);
	ATF_TP_ADD_TC(tp, clofork_unlocked_flag_controls);
	ATF_TP_ADD_TC(tp, clofork_limit_f_setfd_unaffected);

	/* combined */
	ATF_TP_ADD_TC(tp, propagation_once_scm_rights);
	ATF_TP_ADD_TC(tp, propagation_once_dup);
	ATF_TP_ADD_TC(tp, full_confinement);
	ATF_TP_ADD_TC(tp, confinement_capmode);

	return (atf_no_error());
}
