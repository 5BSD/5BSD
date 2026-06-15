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
#include <sys/syscall.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
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
#ifndef CAP_CLOFORK_UNLOCKED
#define	CAP_CLOFORK_UNLOCKED	0
#define	CAP_CLOFORK_LOCKED	1
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
	    "int main(int argc, char **argv) {\n"
	    "    int fd = atoi(argv[1]);\n"
	    "    if (fcntl(fd, F_GETFD) == -1 && errno == EBADF)\n"
	    "        return (0);\n"	/* closed — lock worked */
	    "    return (1);\n"		/* still open — lock didn't work */
	    "}\n");
	fclose(f);
	ATF_REQUIRE(system("cc -o cloexec_helper cloexec_helper.c") == 0);
	exec_helper_path = strdup("./cloexec_helper");
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
	ATF_REQUIRE_ERRNO(EINVAL, cap_cloexec_limit(fd, 2) == -1);

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
	ATF_REQUIRE_ERRNO(EINVAL, cap_clofork_limit(fd, 2) == -1);

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
	ATF_TP_ADD_TC(tp, cloexec_limit_bad_fd);
	ATF_TP_ADD_TC(tp, cloexec_limit_bad_state);
	ATF_TP_ADD_TC(tp, cloexec_limit_same_is_ok);
	ATF_TP_ADD_TC(tp, cloexec_limit_dup_inherits);
	ATF_TP_ADD_TC(tp, cloexec_limit_overrides_flag);
	ATF_TP_ADD_TC(tp, cloexec_unlocked_flag_controls);
	ATF_TP_ADD_TC(tp, cloexec_limit_f_setfd_unaffected);

	/* cap_clofork_limit */
	ATF_TP_ADD_TC(tp, clofork_limit_default);
	ATF_TP_ADD_TC(tp, clofork_limit_widen_fails);
	ATF_TP_ADD_TC(tp, clofork_limit_bad_fd);
	ATF_TP_ADD_TC(tp, clofork_limit_bad_state);
	ATF_TP_ADD_TC(tp, clofork_limit_dup_inherits);
	ATF_TP_ADD_TC(tp, clofork_limit_overrides_flag);
	ATF_TP_ADD_TC(tp, clofork_unlocked_flag_controls);
	ATF_TP_ADD_TC(tp, clofork_limit_f_setfd_unaffected);

	/* combined */
	ATF_TP_ADD_TC(tp, full_confinement);
	ATF_TP_ADD_TC(tp, confinement_capmode);

	return (atf_no_error());
}
