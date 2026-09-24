/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux amd64 modify_ldt reference and VM gate. */
typedef unsigned long u64;
typedef unsigned int u32;
struct user_desc {
	u32 entry_number;
	u32 base_addr;
	u32 limit;
	u32 flags;
};
static unsigned char readbuf[8192 * 8];
static long
call(long n, long a, long b, long c, long d)
{
	register long r10 __asm__("r10") = d;
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
	return (ret);
}
static long
modify(int func, void *ptr, u64 count)
{
	return ((long)(int)call(154, func, (long)ptr, count, 0));
}
static int
is_zero(const unsigned char *p, u64 count)
{
	u64 i;

	for (i = 0; i < count; i++)
		if (p[i] != 0)
			return (0);
	return (1);
}
static int
test(void)
{
	struct user_desc desc = {16, 0x12345000, 0xfffff, 1 | 16 | 64};
	int status;
	long pid;
	u64 i;

	for (i = 0; i < sizeof(readbuf); i++)
		readbuf[i] = 0x5a;
	if (modify(2, readbuf, 128) != 128 || !is_zero(readbuf, 128) ||
	    modify(0, readbuf, 128) != 0)
		return (1);
	if (modify(3, readbuf, 8) != -38 ||
	    modify(0x11, &desc, sizeof(desc) - 1) != -22 ||
	    modify(0x11, (void *)1, sizeof(desc)) != -14)
		return (2);
	desc.entry_number = 8192;
	if (modify(0x11, &desc, sizeof(desc)) != -22)
		return (3);
	desc.entry_number = 16;
	desc.flags |= 3 << 1;
	if (modify(1, &desc, sizeof(desc)) != -22 ||
	    modify(0x11, &desc, sizeof(desc)) != -22)
		return (4);
	desc.flags = 1 | 16 | 64;
	if (modify(0x11, &desc, sizeof(desc)) != 0)
		return (5);
	for (i = 0; i < 137; i++)
		readbuf[i] = 0x5a;
	if (modify(0, readbuf, 137) != 137 ||
	    !is_zero(readbuf, 16 * 8) ||
	    is_zero(readbuf + 16 * 8, 8) || readbuf[136] != 0)
		return (6);
	pid = call(57, 0, 0, 0, 0);
	if (pid < 0)
		return (7);
	if (pid == 0) {
		call(60, modify(0, readbuf, 136) == 136 &&
		    !is_zero(readbuf + 128, 8) ? 0 : 1, 0, 0, 0);
		__builtin_unreachable();
	}
	if (call(61, pid, (long)&status, 0, 0) != pid || status != 0)
		return (8);
	desc.base_addr = 0;
	desc.limit = 0;
	desc.flags = 8 | 32;
	if (modify(0x11, &desc, sizeof(desc)) != 0 ||
	    modify(0, readbuf, 136) != 136 || !is_zero(readbuf + 128, 8))
		return (9);
	desc.entry_number = 8191;
	desc.base_addr = 0x56789000;
	desc.limit = 0xfffff;
	desc.flags = 1 | 16 | 64;
	if (modify(0x11, &desc, sizeof(desc)) != 0 ||
	    modify(0, readbuf, sizeof(readbuf)) != sizeof(readbuf) ||
	    is_zero(readbuf + sizeof(readbuf) - 8, 8))
		return (10);
	if (modify(0, (void *)1, 8) != -14 ||
	    modify(2, (void *)1, 1) != -14)
		return (11);
	desc.entry_number = 20;
	desc.base_addr = 0x13579000;
	desc.limit = 0xfffff;
	desc.flags = 1 | 16 | 64;
	if (modify(1, &desc, sizeof(desc)) != 0 ||
	    modify(0, readbuf, 20 * 8 + 1) != 20 * 8 + 1 ||
	    is_zero(readbuf + 20 * 8, 1))
		return (12);
	desc.base_addr = 0;
	desc.limit = 0;
	if (modify(1, &desc, sizeof(desc)) != 0 ||
	    modify(0, readbuf, 21 * 8) != 21 * 8 ||
	    !is_zero(readbuf + 20 * 8, 8))
		return (13);
	desc.entry_number = 30;
	desc.base_addr = 0x24680000;
	desc.limit = 0xfffff;
	desc.flags = 1 | 16 | 32 | (3 << 1);
	if (modify(1, &desc, sizeof(desc)) != -22 ||
	    modify(0x11, &desc, sizeof(desc)) != 0 ||
	    modify(0, readbuf, 31 * 8) != 31 * 8 ||
	    is_zero(readbuf + 30 * 8, 8))
		return (14);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0, 0);
	__builtin_unreachable();
}
