/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux amd64 rseq signal-abort contract. */
typedef unsigned long u64;
typedef unsigned int u32;
struct rseq {
	u32 cpu_id_start, cpu_id;
	u64 rseq_cs;
	u32 flags, node_id, mm_cid, pad;
} __attribute__((aligned(32)));
struct sigaction {
	void (*handler)(int);
	u64 flags;
	void (*restorer)(void);
	u64 mask;
};
struct rseq_cs {
	u32 version, flags;
	u64 start_ip, post_commit_offset, abort_ip;
} __attribute__((aligned(32)));
struct stack {
	void *sp;
	u32 flags, pad;
	u64 size;
};
char alternate_stack[16384] __attribute__((aligned(16)));
struct rseq rseq_area;
volatile u64 committed, aborted;
u32 test_pid, test_tid;
u64 test_cpu1_mask = 2;
static volatile u32 hits, alt_hits;
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
__asm__(".globl rseq_restorer\n"
    "rseq_restorer:\n mov $15,%eax\n syscall\n hlt\n"
    ".globl rseq_run_cs\n"
    "rseq_run_cs:\n"
    " mov %rdi,rseq_area+8(%rip)\n"
    ".globl rseq_start\n"
    "rseq_start:\n"
    " mov test_pid(%rip),%edi\n"
    " mov test_tid(%rip),%esi\n"
    " mov $10,%edx\n"
    " mov $234,%eax\n"
    " syscall\n"
    " incq committed(%rip)\n"
    ".globl rseq_post_commit\n"
    "rseq_post_commit:\n"
    " movq $0,rseq_area+8(%rip)\n"
    " ret\n"
    " .long 0x53053053\n"
    ".globl rseq_abort\n"
    "rseq_abort:\n"
    " movq $0,rseq_area+8(%rip)\n"
    " incq aborted(%rip)\n"
    " ret\n"
    " .balign 32\n"
    ".globl rseq_descriptor\n"
    "rseq_descriptor:\n"
    " .long 0,0\n"
    " .quad rseq_start\n"
    " .quad rseq_post_commit-rseq_start\n"
    " .quad rseq_abort\n"
    " .long 0\n"
    "rseq_bad_abort:\n ret\n"
    " .balign 32\n"
    " .globl rseq_bad_signature_descriptor\n"
    "rseq_bad_signature_descriptor:\n"
    " .long 0,0\n"
    " .quad rseq_start\n"
    " .quad rseq_post_commit-rseq_start\n"
    " .quad rseq_bad_abort\n"
    ".globl rseq_run_migrate\n"
    "rseq_run_migrate:\n"
    " lea rseq_migrate_descriptor(%rip),%rax\n"
    " mov %rax,rseq_area+8(%rip)\n"
    "rseq_migrate_start:\n"
    " mov test_tid(%rip),%edi\n"
    " mov $8,%esi\n"
    " lea test_cpu1_mask(%rip),%rdx\n"
    " mov $203,%eax\n"
    " syscall\n"
    " incq committed(%rip)\n"
    "rseq_migrate_post_commit:\n"
    " movq $0,rseq_area+8(%rip)\n"
    " ret\n"
    " .long 0x53053053\n"
    "rseq_migrate_abort:\n"
    " movq $0,rseq_area+8(%rip)\n"
    " incq aborted(%rip)\n"
    " ret\n"
    " .balign 32\n"
    "rseq_migrate_descriptor:\n"
    " .long 0,0\n"
    " .quad rseq_migrate_start\n"
    " .quad rseq_migrate_post_commit-rseq_migrate_start\n"
    " .quad rseq_migrate_abort\n");
void rseq_restorer(void);
void rseq_run_cs(void *);
void rseq_run_migrate(void);
extern char rseq_descriptor, rseq_bad_signature_descriptor;
extern char rseq_start, rseq_post_commit, rseq_abort;
static void
handler(int sig)
{
	u64 sp;

	__asm__ volatile("mov %%rsp,%0" : "=r"(sp));
	if (sig == 10) {
		hits++;
		if (sp >= (u64)alternate_stack &&
		    sp < (u64)(alternate_stack + sizeof(alternate_stack)))
			alt_hits++;
	}
}
static int
test(void)
{
	struct sigaction action = { handler,
	    0x04000000 | 0x08000000 | 0x10000000, rseq_restorer, 0 };
	struct stack alt = { alternate_stack, 0, 0,
	    sizeof(alternate_stack) };
	struct sigaction old;
	u64 cpu0 = 1;
	u32 i;
	long child;
	struct rseq_cs bad;
	u32 status, cpu = 0, node = 0;

	if (call(203, 0, sizeof(cpu0), (long)&cpu0, 0) != 0)
		return (1);
	if (call(131, (long)&alt, 0, 0, 0) != 0 ||
	    call(13, 10, (long)&action, (long)&old, 8) != 0)
		return (2);
	test_pid = (u32)call(39, 0, 0, 0, 0);
	test_tid = (u32)call(186, 0, 0, 0, 0);
	if (call(334, (long)&rseq_area, 32, 0, 0x53053053) != 0)
		return (3);
	for (i = 1; i <= 32; i++) {
		rseq_run_cs(&rseq_descriptor);
		if (committed != 0 || aborted != i || hits != i ||
		    alt_hits != i || rseq_area.rseq_cs != 0)
			return (4);
	}
	rseq_run_migrate();
	if (committed != 0 || aborted != 33 || rseq_area.rseq_cs != 0)
		return (5);
	if (call(309, (long)&cpu, (long)&node, 0, 0) != 0 ||
	    cpu != 1 || rseq_area.cpu_id != cpu ||
	    rseq_area.cpu_id_start != cpu)
		return (9);
	{
		u64 blocked = 1UL << 9, oldmask = 0;

		if (call(14, 0, (long)&blocked, (long)&oldmask, 8) != 0)
			return (11);
		rseq_run_cs(&rseq_descriptor);
		if (committed != 1 || aborted != 33 || hits != 32)
			return (12);
		/* A blocked signal must not use the area after unregister. */
		if (call(334, (long)&rseq_area, 32, 1, 0x53053053) != 0 ||
		    rseq_area.cpu_id_start != 0 || rseq_area.cpu_id != (u32)-1)
			return (10);
		if (call(14, 2, (long)&oldmask, 0, 8) != 0 ||
		    hits != 33 || alt_hits != 33 ||
		    rseq_area.cpu_id_start != 0 || rseq_area.cpu_id != (u32)-1)
			return (13);
	}
	for (i = 0; i < 8; i++) {
		child = call(57, 0, 0, 0, 0);
		if (child < 0)
			return (6);
		if (child == 0) {
			test_pid = (u32)call(39, 0, 0, 0, 0);
			test_tid = (u32)call(186, 0, 0, 0, 0);
			if (i == 4 && call(203, 0, sizeof(cpu0),
			    (long)&cpu0, 0) != 0)
				call(60, 103, 0, 0, 0);
			if (call(334, (long)&rseq_area, 32, 0,
			    0x53053053) != 0)
				call(60, 101, 0, 0, 0);
			bad.version = 0;
			bad.flags = 0;
			bad.start_ip = (u64)&rseq_start;
			bad.post_commit_offset = (u64)&rseq_post_commit -
			    (u64)&rseq_start;
			bad.abort_ip = (u64)&rseq_abort;
			if (i == 0)
				rseq_run_cs(&rseq_bad_signature_descriptor);
			else if (i == 1) {
				bad.version = 1;
				rseq_run_cs(&bad);
			} else if (i == 2) {
				bad.flags = 8;
				rseq_run_cs(&bad);
			} else if (i == 3)
				rseq_run_cs((void *)32);
			else if (i == 4) {
				u64 cpu1 = 2;
				u64 page = (u64)&rseq_area & ~4095UL;

				if (call(11, page, 4096, 0, 0) != 0)
					call(60, 104, 0, 0, 0);
				call(203, 0, sizeof(cpu1), (long)&cpu1, 0);
			} else if (i == 5) {
				bad.post_commit_offset = ~(u64)0;
				rseq_run_cs(&bad);
			} else if (i == 6) {
				bad.abort_ip = ~(u64)0;
				rseq_run_cs(&bad);
			} else {
				bad.abort_ip = (u64)&rseq_start + 1;
				rseq_run_cs(&bad);
			}
			call(60, 102, 0, 0, 0);
		}
		if (call(61, child, (long)&status, 0, 0) != child ||
		    (status & 0x7f) != 11)
			return (7 + i);
	}
	if (call(13, 10, (long)&old, 0, 8) != 0)
		return (8);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0, 0);
	__builtin_unreachable();
}
