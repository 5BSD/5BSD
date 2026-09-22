/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 rseq and I/O bitmap ptrace query oracle. */
#include "linux_test.h"
static unsigned char area[32] __attribute__((aligned(32)));
static unsigned char bitmap[8200];
struct conf {
	u64 pointer;
	u32 size, signature, flags, pad;
};
struct vec {
	void *base;
	u64 len;
};
static long child;
static long
pt(long op, u64 addr, u64 data)
{
	return sys4(101, op, child, addr, data);
}
static long
getio(u64 size)
{
	struct vec v = { bitmap, size };
	long ret = pt(0x4204, 0x201, (u64)&v);
	if (!ret && v.len != (size > 8192 ? 8192 : size))
		return -999;
	return ret;
}
static int
waitstop(void)
{
	int st;
	return sys4(SYS_wait4, child, &st, 0, 0) != child || st != 0x57f;
}
static int
test(int argc, char **argv, char **envp)
{
	struct conf c;
	int st;
	(void)argc;
	(void)argv;
	(void)envp;
	child = fork_process();
	if (child < 0)
		return 1;
	if (!child) {
		if (sys4(101, 0, 0, 0, 0))
			sys1(SYS_exit, 90);
		__asm__ volatile("int3" ::: "memory");
		if (sys4(334, area, 32, 0, 0x53053053))
			sys1(SYS_exit, 91);
		if (sys3(173, 0x80, 1, 1))
			sys1(SYS_exit, 92);
		__asm__ volatile("int3" ::: "memory");
		if (sys3(173, 0x80, 1, 0))
			sys1(SYS_exit, 93);
		if (sys4(334, area, 32, 1, 0x53053053))
			sys1(SYS_exit, 94);
		__asm__ volatile("int3" ::: "memory");
		sys1(SYS_exit, 0);
	}
	if (waitstop())
		return 2;
	if (pt(0x420f, 24, (u64)&c) != 24 || c.pointer || c.size ||
	    c.signature || c.flags || c.pad)
		return 3;
	if (pt(0x420f, 0, 1) != 24 || pt(0x420f, 24, 1) != -EFAULT)
		return 4;
	if (getio(8192) != -ENXIO)
		return 5;
	if (pt(7, 0, 0) || waitstop())
		return 6;
	if (pt(0x420f, 24, (u64)&c) != 24 || c.pointer != (u64)area ||
	    c.size != 32 || c.signature != 0x53053053 || c.flags || c.pad)
		return 7;
	c.pointer = 0;
	if (pt(0x420f, 1, (u64)&c) != 24 ||
	    (c.pointer & 255) != ((u64)area & 255) || c.pointer > 255)
		return 8;
	xmemset(bitmap, 0x42, sizeof(bitmap));
	if (getio(sizeof(bitmap)))
		return 9;
	for (int i = 0; i < 8192; i++)
		if (bitmap[i] != (i == 16 ? 0xfe : 0xff))
			return 10;
	if (bitmap[8192] != 0x42 || getio(0) || getio(7) != -EINVAL || getio(8))
		return 11;
	if (pt(7, 0, 0) || waitstop())
		return 12;
	if (getio(8192) != -ENXIO)
		return 13;
	if (pt(0x420f, 24, (u64)&c) != 24 || c.pointer || c.size || c.signature)
		return 14;
	if (pt(7, 0, 0) || sys4(SYS_wait4, child, &st, 0, 0) != child || st)
		return 15;
	return 0;
}
