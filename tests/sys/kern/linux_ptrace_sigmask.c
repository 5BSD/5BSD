/* SPDX-License-Identifier: BSD-2-Clause */
#include "linux_test.h"
static int
test(int argc, char **argv, char **envp)
{
	long p, ret;
	int st;
	u64 mask, original = 1UL << 9;
	u64 wanted = (1UL << 11) | (1UL << 63);
	(void)argc;
	(void)argv;
	(void)envp;
	p = fork_process();
	if (p < 0)
		return 1;
	if (!p) {
		if (sys4(SYS_rt_sigprocmask, 2, &original, 0, 8) ||
		    sys4(101, 0, 0, 0, 0))
			sys1(SYS_exit, 90);
		__asm__ volatile("int3" ::: "memory");
		if (sys4(SYS_rt_sigprocmask, 2, 0, &mask, 8) || mask != wanted)
			sys1(SYS_exit, 91);
		sys1(SYS_exit, 0);
	}
	if (sys4(SYS_wait4, p, &st, 0, 0) != p || st != 0x57f)
		return 2;
	if (sys4(101, 0x420a, p, 8, &mask) || mask != original)
		return 3;
	for (int op = 0x420a; op <= 0x420b; op++) {
		for (int n = 0; n <= 16; n++) {
			if (n == 8)
				continue;
			ret = sys4(101, op, p, n, &mask);
			if (ret != -EINVAL)
				return 4;
		}
		if (sys4(101, op, p, 8, 1) != -EFAULT)
			return 5;
	}
	mask = wanted | (1UL << 8) | (1UL << 18);
	if (sys4(101, 0x420b, p, 8, &mask) || sys4(101, 0x420a, p, 8, &mask) ||
	    mask != wanted)
		return 6;
	if (sys4(101, 7, p, 0, 0) || sys4(SYS_wait4, p, &st, 0, 0) != p || st)
		return 7;
	return 0;
}
