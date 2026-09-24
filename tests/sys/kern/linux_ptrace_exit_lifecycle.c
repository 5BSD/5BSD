/* SPDX-License-Identifier: BSD-2-Clause */
/* Exit-stop lifetime probe; disposable Linux64 guests only. */
#include "linux_test.h"
static int
test(int argc, char **argv, char **envp)
{
	(void)argc; (void)argv; (void)envp;
	for (int round = 0; round < 8; round++) {
		long pid = fork_process(); int st;
		if (pid < 0) return 1;
		if (!pid) {
			if (sys4(101, 0, 0, 0, 0)) sys1(SYS_exit, 90);
			sys2(SYS_kill, sys0(SYS_getpid), 19);
			sys1(SYS_exit, 7);
		}
		if (sys4(SYS_wait4, pid, &st, 0, 0) != pid || st != 0x137f) return 2;
		if (sys4(101, 0x4200, pid, 0, 64) || sys4(101, 7, pid, 0, 0)) return 3;
		if (sys4(SYS_wait4, pid, &st, 0, 0) != pid || st != 0x6057f) return 4;
		long rc = sys4(101, 17, pid, 0, 0);
		if (rc) return 5;
		if (sys4(SYS_wait4, pid, &st, 0, 0) != pid || st != 7 << 8) return 6;
	}
	wr1("EXIT_LIFETIME_PASS\n");
	return 0;
}
