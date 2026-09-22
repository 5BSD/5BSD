/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux amd64 rseq exec success/failure and per-thread reset contract. */
typedef unsigned long u64;
typedef unsigned int u32;
struct rseq {
	u32 cpu_id_start, cpu_id;
	u64 rseq_cs;
	u32 flags, node_id, mm_cid, pad;
} __attribute__((aligned(32)));
static struct rseq area;
static long
call(long n, long a, long b, long c, long d)
{
	register long r10 __asm__("r10") = d, r8 __asm__("r8") = 0,
	    r9 __asm__("r9") = 0;
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (ret);
}
static __attribute__((used)) int
entry(long *stack)
{
	long argc = stack[0];
	char **argv = (char **)(stack + 1);
	char **envp = argv + argc + 1;
	char *next_argv[3] = { argv[0], "after", 0 };
	u64 cpu0 = 1;

	if (argc != 1 && (argc != 2 || argv[1][0] != 'a'))
		return (1);
	if (call(203, 0, sizeof(cpu0), (long)&cpu0, 0) != 0)
		return (2);
	if (call(334, (long)&area, 32, 0, 0x53053053) != 0)
		return (3);
	if (area.cpu_id != 0 || area.cpu_id_start != 0)
		return (4);
	if (argc == 2) {
		if (call(334, (long)&area, 32, 1, 0x53053053) != 0)
			return (5);
		return (0);
	}
	if (call(59, (long)"/no-such-rseq-test", (long)next_argv,
	    (long)envp, 0) != -2)
		return (6);
	if (call(334, (long)&area, 32, 0, 0x53053053) != -16)
		return (7);
	call(59, (long)argv[0], (long)next_argv, (long)envp, 0);
	return (8);
}
__asm__(".globl _start\n_start:\n"
    " mov %rsp,%rdi\n"
    " and $-16,%rsp\n"
    " call entry\n"
    " mov %eax,%edi\n"
    " mov $231,%eax\n"
    " syscall\n hlt\n");
