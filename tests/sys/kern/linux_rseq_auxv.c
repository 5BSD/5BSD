/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux amd64 rseq auxiliary-vector feature and allocation contract. */
typedef unsigned long u64;
typedef unsigned int u32;
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
static unsigned char area[64] __attribute__((aligned(32)));
__attribute__((used, noinline)) static int
test(u64 *stack)
{
	u64 *p = stack + 1 + *stack;
	u64 size = 0, align = 0, type;

	if (*p++ != 0)
		return (1);
	while (*p++ != 0)
		;
	for (; (type = *p++) != 0; p++) {
		if (type == 27) {
			if (size != 0)
				return (2);
			size = *p;
		} else if (type == 28) {
			if (align != 0)
				return (3);
			align = *p;
		}
	}
	if (size < 28 || size > sizeof(area) || align != 32)
		return (4);
#ifdef EXPECT_RSEQ_FEATURE_SIZE
	if (size != EXPECT_RSEQ_FEATURE_SIZE)
		return (5);
#endif
	if (call(334, (long)area, size < 32 ? 32 : size, 0,
	    0x53053053) != 0)
		return (6);
	if (*(u32 *)(area + 4) == (u32)-1 ||
	    *(u32 *)(area + 4) != *(u32 *)area)
		return (7);
	if (call(334, (long)area, size < 32 ? 32 : size, 1,
	    0x53053053) != 0)
		return (8);
	return (0);
}
__asm__(".global _start\n_start:\n"
    "mov %rsp, %rdi\n"
    "call test\n"
    "mov %eax, %edi\n"
    "mov $60, %eax\n"
    "syscall\n");
