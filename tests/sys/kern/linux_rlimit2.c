/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The rlimits FreeBSD does not have (RLIMIT_NICE, RTPRIO, RTTIME, LOCKS,
 * SIGPENDING, MSGQUEUE) through getrlimit/setrlimit/prlimit64, plus the
 * kcmp(2) types that are EOPNOTSUPP.  Exit status = failed check number.
 */
#include "linux_test.h"

#define	RLIMIT_NOFILE		7
#define	RLIMIT_LOCKS		10
#define	RLIMIT_SIGPENDING	11
#define	RLIMIT_MSGQUEUE		12
#define	RLIMIT_NICE		13
#define	RLIMIT_RTPRIO		14
#define	RLIMIT_RTTIME		15
#define	KCMP_FILE		0
#define	KCMP_VM			1
#define	KCMP_FILES		2
#define	KCMP_FS			3
#define	KCMP_SIGHAND		4
#define	KCMP_IO			5
#define	KCMP_SYSVSEM		6
#define	KCMP_EPOLL_TFD		7

static int
test(int argc, char **argv, char **envp)
{
	struct rlimit rl, old;
	long pid, fd;

	(void)argc; (void)argv; (void)envp;

	/* 1-2: NICE and RTPRIO are 0/0 (nothing may be raised unprivileged). */
	if (sys2(SYS_getrlimit, RLIMIT_NICE, &rl) != 0) return (1);
	if (rl.rlim_cur != 0 || rl.rlim_max != 0) return (1);
	if (sys2(SYS_getrlimit, RLIMIT_RTPRIO, &rl) != 0) return (2);
	if (rl.rlim_cur != 0 || rl.rlim_max != 0) return (2);
	/* 3-4: LOCKS and RTTIME are unlimited. */
	if (sys2(SYS_getrlimit, RLIMIT_LOCKS, &rl) != 0) return (3);
	if (rl.rlim_cur != RLIM_INFINITY || rl.rlim_max != RLIM_INFINITY)
		return (3);
	if (sys2(SYS_getrlimit, RLIMIT_RTTIME, &rl) != 0) return (4);
	if (rl.rlim_cur != RLIM_INFINITY) return (4);
	/* 5-6: SIGPENDING and MSGQUEUE report positive system values. */
	if (sys2(SYS_getrlimit, RLIMIT_SIGPENDING, &rl) != 0) return (5);
	if (rl.rlim_cur == 0 || rl.rlim_cur > rl.rlim_max) return (5);
	if (sys2(SYS_getrlimit, RLIMIT_MSGQUEUE, &rl) != 0) return (6);
	if (rl.rlim_cur == 0) return (6);
	/* 7: an unknown resource is EINVAL. */
	if (sys2(SYS_getrlimit, 16, &rl) != -EINVAL) return (7);
	/* 8: setting NICE to 0/0 succeeds... */
	rl.rlim_cur = 0; rl.rlim_max = 0;
	if (sys2(SYS_setrlimit, RLIMIT_NICE, &rl) != 0) return (8);
	/* 9: ...soft > hard is EINVAL... */
	rl.rlim_cur = 5; rl.rlim_max = 0;
	if (sys2(SYS_setrlimit, RLIMIT_NICE, &rl) != -EINVAL) return (9);
	/* 10: ...root may raise the hard limit (accepted, not enforced). */
	rl.rlim_cur = 10; rl.rlim_max = 20;
	if (sys2(SYS_setrlimit, RLIMIT_NICE, &rl) != 0) return (10);
	/* 11: LOCKS can be set to anything. */
	rl.rlim_cur = 100; rl.rlim_max = RLIM_INFINITY;
	if (sys2(SYS_setrlimit, RLIMIT_LOCKS, &rl) != 0) return (11);
	/* 12-13: prlimit64 reads the same values for self and by pid. */
	pid = sys0(SYS_getpid);
	if (sys4(SYS_prlimit64, 0, RLIMIT_RTPRIO, 0, &rl) != 0) return (12);
	if (rl.rlim_max != 0) return (12);
	if (sys4(SYS_prlimit64, pid, RLIMIT_LOCKS, 0, &rl) != 0) return (13);
	if (rl.rlim_cur != RLIM_INFINITY) return (13);
	/* 14: prlimit64 set with old returns the previous value. */
	rl.rlim_cur = 0; rl.rlim_max = 0;
	if (sys4(SYS_prlimit64, 0, RLIMIT_RTPRIO, &rl, &old) != 0) return (14);
	if (old.rlim_max != 0) return (14);
	/* 15: prlimit64 set of soft > hard is EINVAL. */
	rl.rlim_cur = 1; rl.rlim_max = 0;
	if (sys4(SYS_prlimit64, 0, RLIMIT_RTPRIO, &rl, 0) != -EINVAL) return (15);
	/* 16: a real limit still works through the same path. */
	if (sys4(SYS_prlimit64, 0, RLIMIT_NOFILE, 0, &rl) != 0) return (16);
	if (rl.rlim_cur == 0) return (16);
	/* 17: prlimit64 with an unknown resource is EINVAL. */
	if (sys4(SYS_prlimit64, 0, 16, 0, &rl) != -EINVAL) return (17);
	/* 18: a bad pointer is EFAULT. */
	if (sys2(SYS_getrlimit, RLIMIT_NICE, 0) != -EFAULT) return (18);

	/* 19-21: kcmp. */
	fd = sys1(SYS_dup, 0);
	if (fd < 0) return (19);
	if (sys5(SYS_kcmp, pid, pid, KCMP_FILE, 0, fd) != 0) return (19);
	if (sys5(SYS_kcmp, pid, pid, KCMP_VM, 0, 0) != 0) return (19);
	if (sys5(SYS_kcmp, pid, pid, KCMP_FILES, 0, 0) != 0) return (19);
	if (sys5(SYS_kcmp, pid, pid, KCMP_SIGHAND, 0, 0) != 0) return (19);
	if (sys5(SYS_kcmp, pid, pid, KCMP_FS, 0, 0) != -EOPNOTSUPP) return (20);
	if (sys5(SYS_kcmp, pid, pid, KCMP_IO, 0, 0) != -EOPNOTSUPP) return (20);
	if (sys5(SYS_kcmp, pid, pid, KCMP_SYSVSEM, 0, 0) != -EOPNOTSUPP)
		return (20);
	if (sys5(SYS_kcmp, pid, pid, KCMP_EPOLL_TFD, 0, 0) != -EOPNOTSUPP)
		return (20);
	if (sys5(SYS_kcmp, pid, pid, 8, 0, 0) != -EINVAL) return (21);
	if (sys5(SYS_kcmp, 999999, pid, KCMP_VM, 0, 0) != -ESRCH) return (21);
	(void)sys1(SYS_close, fd);
	return (0);
}
