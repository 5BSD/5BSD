/* SPDX-License-Identifier: BSD-2-Clause */
/* Same-CPU scheduler preemption must abort an active Linux rseq section. */
typedef unsigned long u64;
typedef unsigned int u32;
struct rseq {
	u32 cpu_id_start, cpu_id;
	u64 rseq_cs;
	u32 flags, node_id, mm_cid, pad;
} __attribute__((aligned(32)));
struct rseq area;
volatile u64 committed, aborted;
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
__asm__(".globl run_cs\n"
    "run_cs:\n"
    " lea descriptor(%rip),%rax\n"
    " mov %rax,area+8(%rip)\n"
    "cs_start:\n"
    " mov $24,%eax\n"
    " syscall\n"
    " incq committed(%rip)\n"
    "cs_end:\n"
    " movq $0,area+8(%rip)\n"
    " ret\n"
    " .long 0x53053053\n"
    "cs_abort:\n"
    " movq $0,area+8(%rip)\n"
    " incq aborted(%rip)\n"
    " ret\n"
    " .balign 32\n"
    "descriptor:\n"
    " .long 0,0\n"
    " .quad cs_start\n"
    " .quad cs_end-cs_start\n"
    " .quad cs_abort\n");
void run_cs(void);
static int
test(void)
{
	int pipefd[2];
	long child;
	u64 cpu0 = 1;
	char ready;
	u32 status;
	int i;

	if (call(203, 0, sizeof(cpu0), (long)&cpu0, 0) != 0)
		return (1);
	if (call(334, (long)&area, 32, 0, 0x53053053) != 0)
		return (2);
	if (call(22, (long)pipefd, 0, 0, 0) != 0)
		return (3);
	child = call(57, 0, 0, 0, 0);
	if (child < 0)
		return (4);
	if (child == 0) {
		call(3, pipefd[0], 0, 0, 0);
		ready = 'x';
		if (call(1, pipefd[1], (long)&ready, 1, 0) != 1)
			call(60, 21, 0, 0, 0);
		for (;;)
			__asm__ volatile("pause" ::: "memory");
	}
	call(3, pipefd[1], 0, 0, 0);
	if (call(0, pipefd[0], (long)&ready, 1, 0) != 1)
		return (5);
	for (i = 0; i < 128; i++) {
		run_cs();
		if (committed + aborted != (u64)(i + 1) || area.rseq_cs != 0)
			return (6);
	}
	if (call(62, child, 9, 0, 0) != 0 ||
	    call(61, child, (long)&status, 0, 0) != child ||
	    (status & 0x7f) != 9)
		return (7);
	if (aborted == 0)
		return (8);
	if (call(334, (long)&area, 32, 1, 0x53053053) != 0)
		return (9);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0, 0);
	__builtin_unreachable();
}
