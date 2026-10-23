/* SPDX-License-Identifier: BSD-2-Clause */
/* Static Linux/RISC-V ELF smoke test; run inside a riscv64 5BSD guest. */
#include "linux_test.h"

#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define SA_ONSTACK 0x08000000UL
#define FUTEX_WAKE_OP 5
#define FUTEX_OP_ADD_THREE_IF_EQUAL_FIVE 0x10003005

struct hwprobe_pair {
	long key;
	unsigned long value;
};

struct linux_sigaction {
	void (*handler)(int);
	unsigned long flags;
	unsigned long mask;
};

struct linux_stack {
	void *sp;
	int flags;
	unsigned long size;
};

struct linux_utsname {
	char sysname[65], nodename[65], release[65], version[65];
	char machine[65], domainname[65];
};

static char altstack[16384] __attribute__((aligned(16)));
static volatile unsigned long handler_sp;
static volatile int received;

static void
signal_handler(int sig)
{
	char local;

	if (sig == SIGUSR1) {
		handler_sp = (unsigned long)&local;
		received++;
	}
}

static int
test(int argc, char **argv, char **envp)
{
	struct linux_sigaction sa;
	struct hwprobe_pair pairs[3];
	struct linux_utsname uts;
	struct linux_stack ss;
	char name[16];
	int futex_a, futex_b, status;
	long child, pid;

	(void)argc;
	(void)argv;
	(void)envp;
	pid = sys0(SYS_getpid);
	if (pid <= 0)
		return (1);
	xmemset(&uts, 0, sizeof(uts));
	if (sys1(SYS_uname, &uts) != 0 || !xstreq(uts.machine, "riscv64"))
		return (2);
	if (sys2(SYS_prctl, PR_SET_NAME, "riscv64-smoke") != 0)
		return (3);
	xmemset(name, 0, sizeof(name));
	if (sys2(SYS_prctl, PR_GET_NAME, name) != 0 ||
	    !xstreq(name, "riscv64-smoke"))
		return (4);
	if (sys1(SYS_unshare, 0) != 0 ||
	    sys1(SYS_unshare, CLONE_NEWNS) != -EINVAL)
		return (5);
	pairs[0].key = 3;
	pairs[1].key = 4;
	pairs[2].key = 9999;
	if (sys5(SYS_riscv_hwprobe, pairs, 3, 0, 0, 0) != 0 ||
	    pairs[0].key != 3 || pairs[1].key != 4 ||
	    pairs[2].key != -1 || pairs[2].value != 0)
		return (6);
	if (sys3(SYS_riscv_flush_icache, 0, 0, 0) != 0 ||
	    sys3(SYS_riscv_flush_icache, 0, 0, 1) != 0 ||
	    sys3(SYS_riscv_flush_icache, 0, 0, 2) != -EINVAL)
		return (7);
	ss.sp = altstack;
	ss.flags = 0;
	ss.size = sizeof(altstack);
	if (sys2(SYS_sigaltstack, &ss, 0) != 0)
		return (8);
	xmemset(&sa, 0, sizeof(sa));
	sa.handler = signal_handler;
	sa.flags = SA_ONSTACK;
	if (sys4(SYS_rt_sigaction, SIGUSR1, &sa, 0, 8) != 0)
		return (9);
	if (sys3(SYS_tgkill, pid, sys0(SYS_gettid), SIGUSR1) != 0 ||
	    received != 1 || handler_sp < (unsigned long)altstack ||
	    handler_sp >= (unsigned long)(altstack + sizeof(altstack)))
		return (10);
	futex_a = 0;
	futex_b = 5;
	if (sys6(SYS_futex, &futex_a, FUTEX_WAKE_OP, 0, 0, &futex_b,
	    FUTEX_OP_ADD_THREE_IF_EQUAL_FIVE) != 0 || futex_b != 8)
		return (11);
	child = sys5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
	if (child == 0)
		sys1(SYS_exit, 42);
	if (child <= 0 || sys4(SYS_wait4, child, &status, 0, 0) != child ||
	    status != (42 << 8))
		return (12);
	return (0);
}
