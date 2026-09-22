/* SPDX-License-Identifier: BSD-2-Clause */
/* Hold an active Linux rseq registration for the module-unload gate. */
typedef unsigned long u64;
typedef unsigned int u32;
struct rseq {
	u32 cpu_id_start, cpu_id;
	u64 rseq_cs;
	u32 flags, node_id, mm_cid, pad;
} __attribute__((aligned(32)));
static struct rseq area;
static const char marker[] = "rseq-active";
static const char ready[] = "ready\n";
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
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	long fd;

	if (call(334, (long)&area, 32, 0, 0x53053053) != 0)
		call(60, 1, 0, 0, 0);
	fd = call(257, -100, (long)marker, 0x241, 0600);
	if (fd < 0 || call(1, fd, (long)ready, sizeof(ready) - 1, 0) !=
	    sizeof(ready) - 1)
		call(60, 2, 0, 0, 0);
	call(3, fd, 0, 0, 0);
	for (;;)
		call(34, 0, 0, 0, 0);
}
