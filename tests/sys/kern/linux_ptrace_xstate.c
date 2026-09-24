/* SPDX-License-Identifier: BSD-2-Clause */
/* Run only in disposable amd64 Linux/Linuxulator guests. */
#include "linux_test.h"
struct vec {
	void *base;
	u64 len;
};
static u8 state[65536] __attribute__((aligned(64)));
static u8 original[65536] __attribute__((aligned(64)));
static long child;
static u64 size;
static long
trace(long req, long addr, void *data)
{
	return sys4(101, req, child, addr, data);
}
static long
get(void)
{
	struct vec v = { state, sizeof(state) };
	long r = trace(0x4204, 0x202, &v);
	size = v.len;
	return r;
}
static long
set(void *data, u64 len)
{
	struct vec v = { data, len };
	long r = trace(0x4205, 0x202, &v);
	if (!r && v.len != size)
		return -999;
	return r;
}
static int no_xsave;
static int
start(void)
{
	int status;
	child = fork_process();
	if (child < 0)
		return 90;
	if (!child) {
		u8 saved[32] __attribute__((aligned(32)));
		if (sys4(101, 0, 0, 0, 0))
			sys1(SYS_exit, 91);
		if (no_xsave) {
			__asm__ volatile("fninit; int3" ::: "memory");
			for (;;)
				__asm__ volatile("int3");
		}
		__asm__ volatile(
		    "fninit; vpcmpeqd %%ymm0,%%ymm0,%%ymm0; int3; vmovdqu %%ymm0,%0; int3"
		    : "=m"(saved)::"ymm0", "memory");
		/* Parent reads this buffer through ptrace after the second
		 * stop. */
		for (;;) {
			__asm__ volatile("int3" ::: "memory");
		}
	}
	if (sys4(SYS_wait4, child, &status, 0, 0) != child || status != 0x57f)
		return 92;
	return 0;
}
static int
finish(int rc)
{
	int status;
	trace(8, 0, 0);
	sys4(SYS_wait4, child, &status, 0, 0);
	return rc;
}
#define CHECK(x, n)                       \
	do {                              \
		if (!(x))                 \
			return finish(n); \
	} while (0)
static void
restore(void)
{
	for (u64 i = 0; i < size; i++)
		state[i] = original[i];
}
static int
test(int argc, char **argv, char **envp)
{
	(void)envp;
	if (argc != 2 && argc != 3)
		return 89;
	if (argc == 3 && xstreq(argv[2], "unprivileged")) {
		if (sys1(106, 60001) || sys1(105, 60001))
			return 93;
		/* Clear the credential-transition tracing restriction via exec. */
		char *av[] = { argv[0], argv[1], 0 }, *ev[] = { 0 };
		sys3(SYS_execve, argv[0], av, ev);
		return 94;
	}
	no_xsave = xstreq(argv[1], "no_xsave");
	int r = start();
	if (r)
		return r;
	if (xstreq(argv[1], "no_xsave")) {
		CHECK(get() == -19, 1);
		CHECK(set(state, 512) == -19, 2);
		return finish(0);
	}
	CHECK(get() == 0 && size >= 832 && size <= sizeof(state), 3);
	for (u64 i = 0; i < size; i++)
		original[i] = state[i];
	if (xstreq(argv[1], "roundtrip")) {
		CHECK(set(state, size) == 0, 10);
		CHECK(get() == 0, 11);
		CHECK(state[160] == 255 && state[576] == 255, 12);
	} else if (xstreq(argv[1], "write_resume")) {
		for (int i = 0; i < 16; i++) {
			state[160 + i] = 0x42;
			state[576 + i] = 0x73;
		}
		*(u64 *)(state + 512) |= 7;
		CHECK(set(state, size) == 0, 20);
		CHECK(trace(7, 0, 0) == 0, 21);
		int status;
		CHECK(sys4(SYS_wait4, child, &status, 0, 0) == child &&
			status == 0x57f,
		    22);
		CHECK(get() == 0, 23);
		for (int i = 0; i < 16; i++)
			CHECK(state[160 + i] == 0x42 && state[576 + i] == 0x73,
			    24);
	} else if (xstreq(argv[1], "lengths")) {
		CHECK(set(state, 0) == -14, 30);
		CHECK(set(state, 512) == -14, 31);
		CHECK(set(state, size - 8) == -14, 32);
		CHECK(set(state, size - 1) == -22, 33);
		CHECK(set(state, size + 8) == 0, 34);
	} else if (xstreq(argv[1], "invalid")) {
		for (int i = 1; i < 8; i++) {
			restore();
			((u64 *)(state + 512))[i] = 1;
			CHECK(set(state, size) == -22, 40 + i);
		}
		restore();
		*(u64 *)(state + 512) |= 1ULL << 63;
		CHECK(set(state, size) == -22, 49);
		restore();
		*(u32 *)(state + 24) = 0xffffffff;
		*(u64 *)(state + 512) |= 7;
		CHECK(set(state, size) == -22, 50);
		CHECK(get() == 0 && state[160] == 255 && state[576] == 255, 51);
	} else if (xstreq(argv[1], "init_state")) {
		*(u64 *)(state + 512) = 0;
		*(u32 *)(state + 24) = 0xffffffff;
		CHECK(set(state, size) == 0, 60);
		CHECK(trace(7, 0, 0) == 0, 61);
		int status;
		CHECK(sys4(SYS_wait4, child, &status, 0, 0) == child &&
			status == 0x57f,
		    62);
		CHECK(get() == 0, 63);
		for (int i = 0; i < 16; i++)
			CHECK(state[160 + i] == 0 && state[576 + i] == 0, 64);
	} else if (xstreq(argv[1], "faults")) {
		CHECK(set(0, size) == -14, 70);
		void *map = (void *)sys6(SYS_mmap, 0, 131072, 3, 0x22, -1, 0);
		CHECK((long)map > 0, 71);
		CHECK(sys3(SYS_mprotect, (char *)map + 65536, 65536, 0) == 0,
		    72);
		CHECK(set((char *)map + 65536 - size + 8, size) == -14, 73);
		CHECK(get() == 0 && state[160] == 255 && state[576] == 255, 74);
		struct vec *v = map;
		v->base = state;
		v->len = size;
		state[160] = 0x52;
		CHECK(sys3(SYS_mprotect, map, 65536, 1) == 0, 75);
		CHECK(trace(0x4205, 0x202, v) == -14, 76);
		CHECK(get() == 0 && state[160] == 0x52, 77);
		sys2(SYS_munmap, map, 131072);
	} else if (xstreq(argv[1], "metadata")) {
		for (int i = 464; i < 512; i++)
			state[i] = 0xff;
		CHECK(set(state, size) == 0, 80);
		CHECK(get() == 0 && state[160] == 255, 81);
	} else
		return finish(88);
	return finish(0);
}
