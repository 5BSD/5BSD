/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux amd64 rseq registration contract. */
typedef unsigned long u64;
typedef unsigned int u32;
struct rseq {
	u32 cpu_id_start, cpu_id;
	u64 rseq_cs;
	u32 flags, node_id, mm_cid, pad;
} __attribute__((aligned(32)));
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
static long
rseq(void *area, u32 length, int flags, u32 sig)
{
	return (call(334, (long)area, length, flags, sig));
}
static int
test(void)
{
	static unsigned char first[64] __attribute__((aligned(32)));
	static unsigned char second[64] __attribute__((aligned(32)));
	struct rseq *r = (struct rseq *)first;
	u32 cpu = 0, node = 0;
	u64 affinity = 1;
	const u32 sig = 0x53053053;

	if (call(203, 0, sizeof(affinity), (long)&affinity, 0) != 0)
		return (9);
	if (rseq(first, 31, 0, sig) != -22 ||
	    rseq(first, 32, 2, sig) != -22 ||
	    rseq(first + 1, 32, 0, sig) != -22 ||
	    rseq((void *)32, 32, 0, sig) != -14)
		return (1);
	if (rseq(first, 33, 0, sig) != 0 ||
	    rseq(first, 33, 1, sig) != 0)
		return (2);
	if (rseq(first, 32, 0, sig) != 0)
		return (3);
	if (call(309, (long)&cpu, (long)&node, 0, 0) != 0 ||
	    r->cpu_id != cpu || r->cpu_id_start != cpu ||
	    r->rseq_cs != 0)
		return (4);
	if (rseq(first, 32, 0, sig) != -16 ||
	    rseq(first, 32, 0, sig + 1) != -1 ||
	    rseq(second, 32, 0, sig) != -22)
		return (5);
	if (rseq(second, 32, 1, sig) != -22 ||
	    rseq(first, 31, 1, sig) != -22 ||
	    rseq(first, 32, 1, sig + 1) != -1)
		return (6);
	if (rseq(first, 32, 1, sig) != 0 ||
	    r->cpu_id_start != 0 || r->cpu_id != (u32)-1 ||
	    rseq(first, 32, 1, sig) != -22)
		return (7);
	if (rseq(second, 64, 0, sig) != 0 ||
	    rseq(second, 64, 1, sig) != 0)
		return (8);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0, 0);
	__builtin_unreachable();
}
