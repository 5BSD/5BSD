/* SPDX-License-Identifier: BSD-2-Clause */
#include "linux_test.h"
/*
 * mlockall(2)/munlockall(2) flag validation incl. MCL_ONFAULT (Linux 4.4),
 * and getrandom(2) flags incl. GRND_INSECURE (Linux 5.6).  Exit status =
 * failed check number.
 */
#define	MCL_CURRENT	1
#define	MCL_FUTURE	2
#define	MCL_ONFAULT	4
#define	GRND_NONBLOCK	1
#define	GRND_RANDOM	2
#define	GRND_INSECURE	4

static int
test(int argc, char **argv, char **envp)
{
	unsigned char buf[64], zeros[64];
	long r, i, p;
	volatile char *c;

	(void)argc; (void)argv; (void)envp;

	/* 1: MCL_CURRENT locks what is mapped now. */
	if (sys1(SYS_mlockall, MCL_CURRENT) != 0) return (1);
	if (sys0(SYS_munlockall) != 0) return (1);
	/* 2: MCL_FUTURE, 3: both. */
	if (sys1(SYS_mlockall, MCL_FUTURE) != 0) return (2);
	if (sys0(SYS_munlockall) != 0) return (2);
	if (sys1(SYS_mlockall, MCL_CURRENT | MCL_FUTURE) != 0) return (3);
	if (sys0(SYS_munlockall) != 0) return (3);
	/* 4: MCL_ONFAULT with CURRENT is accepted (wired eagerly here). */
	if (sys1(SYS_mlockall, MCL_CURRENT | MCL_ONFAULT) != 0) return (4);
	if (sys0(SYS_munlockall) != 0) return (4);
	/* 5: MCL_FUTURE|MCL_ONFAULT: a later mapping is usable. */
	if (sys1(SYS_mlockall, MCL_FUTURE | MCL_ONFAULT) != 0) return (5);
	p = call(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p < 0) return (5);
	c = (volatile char *)p;
	c[0] = 1;
	(void)sys2(SYS_munmap, p, PAGE);
	if (sys0(SYS_munlockall) != 0) return (5);
	/* 6: MCL_ONFAULT alone is EINVAL. */
	if (sys1(SYS_mlockall, MCL_ONFAULT) != -EINVAL) return (6);
	/* 7: no flags is EINVAL. */
	if (sys1(SYS_mlockall, 0) != -EINVAL) return (7);
	/* 8: unknown bits are EINVAL. */
	if (sys1(SYS_mlockall, 8) != -EINVAL) return (8);
	if (sys1(SYS_mlockall, MCL_CURRENT | 0x100) != -EINVAL) return (8);
	/* 9: munlockall when nothing is locked is fine. */
	if (sys0(SYS_munlockall) != 0) return (9);

	/* 10: getrandom fills the buffer. */
	xmemset(buf, 0, sizeof(buf));
	xmemset(zeros, 0, sizeof(zeros));
	if (sys3(SYS_getrandom, buf, sizeof(buf), 0) != (long)sizeof(buf))
		return (10);
	if (xmemcmp(buf, zeros, sizeof(buf)) == 0) return (10);
	/* 11: GRND_NONBLOCK and GRND_RANDOM are accepted. */
	if (sys3(SYS_getrandom, buf, 16, GRND_NONBLOCK) != 16) return (11);
	r = sys3(SYS_getrandom, buf, 16, GRND_RANDOM);
	if (r < 0 && r != -EAGAIN) return (11);
	/* 12: GRND_INSECURE never blocks and returns data. */
	xmemset(buf, 0, sizeof(buf));
	if (sys3(SYS_getrandom, buf, sizeof(buf), GRND_INSECURE) !=
	    (long)sizeof(buf)) return (12);
	if (xmemcmp(buf, zeros, sizeof(buf)) == 0) return (12);
	/* 13: GRND_INSECURE|GRND_RANDOM is EINVAL. */
	if (sys3(SYS_getrandom, buf, 16, GRND_INSECURE | GRND_RANDOM) !=
	    -EINVAL) return (13);
	/* 14: unknown flag bits are EINVAL. */
	if (sys3(SYS_getrandom, buf, 16, 8) != -EINVAL) return (14);
	/* 15: a zero count returns 0. */
	if (sys3(SYS_getrandom, buf, 0, 0) != 0) return (15);
	/* 16: a bad buffer is EFAULT. */
	if (sys3(SYS_getrandom, 0, 16, 0) != -EFAULT) return (16);
	/* 17: two calls do not return the same bytes. */
	if (sys3(SYS_getrandom, buf, 32, 0) != 32) return (17);
	if (sys3(SYS_getrandom, zeros, 32, 0) != 32) return (17);
	for (i = 0; i < 32 && buf[i] == zeros[i]; i++)
		;
	if (i == 32) return (17);
	return (0);
}

