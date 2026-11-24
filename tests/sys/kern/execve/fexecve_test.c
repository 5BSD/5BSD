/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 */

/*
 * fexecve(2) answers through fgetvp_exec(): the descriptor checks of
 * _fget(FEXEC), then the file's vnode.  These pin what every descriptor
 * type that is not a served one gets, so a change to fgetvp_exec() for
 * served files leaves them as they are.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define	TRUE_PATH	"/usr/bin/true"

/*
 * fexecve(fd) in a child: its exit status is 0 when the exec ran the
 * program, or 100 + errno when fexecve returned.
 */
static int
child_fexecve(int fd)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envp[] = { NULL };
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		(void)fexecve(fd, argv, envp);
		_exit(100 + errno);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

#define	SHM_PATH	"/fexecve_test_shm"

ATF_TC_WITHOUT_HEAD(fexecve_novnode_einval);
ATF_TC_BODY(fexecve_novnode_einval, tc)
{
	int fd, p[2];

	/* Both ends of a pipe are FREAD | FWRITE: _fget(FEXEC) refuses. */
	ATF_REQUIRE_EQ(0, pipe(p));
	ATF_CHECK_EQ(100 + EBADF, child_fexecve(p[0]));
	ATF_CHECK_EQ(100 + EBADF, child_fexecve(p[1]));
	(void)close(p[0]);
	(void)close(p[1]);
	/* A read-only descriptor with no vnode: EINVAL. */
	(void)shm_unlink(SHM_PATH);
	fd = shm_open(SHM_PATH, O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	(void)close(fd);
	fd = shm_open(SHM_PATH, O_RDONLY, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(100 + EINVAL, child_fexecve(fd));
	(void)close(fd);
	(void)shm_unlink(SHM_PATH);
}

ATF_TC_WITHOUT_HEAD(fexecve_real_file);
ATF_TC_BODY(fexecve_real_file, tc)
{
	int fd;

	fd = open(TRUE_PATH, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(0, child_fexecve(fd));
	(void)close(fd);
	fd = open(TRUE_PATH, O_EXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(0, child_fexecve(fd));
	(void)close(fd);
	/* Open for writing: _fget(FEXEC) refuses it. */
	fd = open("w", O_RDWR | O_CREAT, 0755);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(100 + EBADF, child_fexecve(fd));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(fexecve_opath_real);
ATF_TC_BODY(fexecve_opath_real, tc)
{
	int fd;

	/* An O_PATH descriptor passes _fget(FEXEC) and names its vnode. */
	fd = open(TRUE_PATH, O_PATH);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(0, child_fexecve(fd));
	(void)close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fexecve_novnode_einval);
	ATF_TP_ADD_TC(tp, fexecve_real_file);
	ATF_TP_ADD_TC(tp, fexecve_opath_real);
	return (atf_no_error());
}
