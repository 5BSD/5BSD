/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding amd64 Linux ABI oracle; execute only in disposable guests. */
#include "linux_test.h"
#define PTRACE	 101
#define GETREGS	 12
#define SETREGS	 13
#define GETFP	 14
#define SETFP	 15
#define GETSET	 0x4204
#define SETSET	 0x4205
#define PRSTATUS 1
#define FPREG	 2
#define XSTATE	 0x202
struct vec {
	void *base;
	u64 len;
};
struct regs {
	u64 r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi,
	    rdi, orig, rip, cs, flags, rsp, ss, fsbase, gsbase, ds, es, fs, gs;
};
static unsigned char fp[512] __attribute__((aligned(64)));
static unsigned char xs[16384] __attribute__((aligned(64)));
static long child;
static char *self_path;
static int change;
static long
pt(long req, long note, void *data)
{
	return sys4(PTRACE, req, child, note, data);
}
static long
regset(long req, long note, void *data, u64 len)
{
	struct vec v = { data, len };
	return pt(req, note, &v);
}
static int
has_avx(void)
{
	unsigned int a = 1, b, c, d;
	__asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
	return (c & (1U << 28)) && (c & (1U << 27));
}
static int
start(int mode)
{
	int st;
	long p = fork_process();
	if (p < 0)
		return 90;
	if (p == 0) {
		unsigned char saved[512] __attribute__((aligned(16)));
		u64 r;
		if (sys4(PTRACE, 0, 0, 0, 0) != 0)
			sys1(SYS_exit, 91);
		if (sys2(158, 0x1002, 0x12345000) != 0 ||
		    sys2(158, 0x1001, 0x23456000) != 0)
			sys1(SYS_exit, 92);
		if (has_avx())
			__asm__ volatile("vpcmpeqd %%ymm1,%%ymm1,%%ymm1" ::
				: "ymm1");
		__asm__ volatile(
		    "fninit; fld1; pcmpeqd %%xmm0,%%xmm0; mov $0x1234,%%r12; int3; fxsave %0; mov %%r12,%1"
		    : "=m"(saved), "=m"(r)
		    :
		    : "r12", "xmm0", "memory");
		if (mode == 1 && saved[160] != 0x42)
			sys1(SYS_exit, 93);
		if (mode == 2 && r != 0x5678)
			sys1(SYS_exit, 94);
		sys1(SYS_exit, 0);
		for (;;) {
		}
	}
	child = p;
	change = mode;
	if (sys4(SYS_wait4, p, &st, 2, 0) != p || (st & 255) != 127 ||
	    ((st >> 8) & 255) != 5)
		return 95;
	return 0;
}
static int
finish(int result)
{
	int st;
	if (pt(7, 0, 0) != 0)
		return 96;
	if (sys4(SYS_wait4, child, &st, 0, 0) != child)
		return 97;
	return result ? result : (st == 0 ? 0 : 98);
}
#define CHECK(x, n)                       \
	do {                              \
		if (!(x))                 \
			return finish(n); \
	} while (0)
static int
fp_read(void)
{
	struct vec v = { xs, sizeof(xs) };
	int e = start(0);
	if (e)
		return e;
	CHECK(pt(GETFP, 0, fp) == 0, 1);
	CHECK(*(u16 *)fp == 0x37f && fp[160] == 255 && fp[175] == 255, 2);
	CHECK(pt(GETSET, FPREG, &v) == 0 && v.len == 512 &&
		xmemcmp(fp, xs, 512) == 0,
	    3);
	return finish(0);
}
static int
fp_write(void)
{
	int e = start(1);
	if (e)
		return e;
	CHECK(pt(GETFP, 0, fp) == 0, 1);
	fp[160] = 0x42;
	CHECK(pt(SETFP, 0, fp) == 0, 2);
	CHECK(pt(GETFP, 0, xs) == 0 && xs[160] == 0x42, 3);
	return finish(0);
}
static int
fp_setregset(void)
{
	int e = start(1);
	if (e)
		return e;
	CHECK(pt(GETFP, 0, fp) == 0, 1);
	fp[160] = 0x42;
	CHECK(regset(SETSET, FPREG, fp, 168) == -EINVAL, 2);
	CHECK(regset(SETSET, FPREG, fp, 512) == 0, 4);
	CHECK(pt(GETFP, 0, xs) == 0 && xs[160] == 0x42 && xs[175] == 255, 3);
	return finish(0);
}
static int
fp_bad_mxcsr(void)
{
	int e = start(0);
	if (e)
		return e;
	CHECK(pt(GETFP, 0, fp) == 0, 1);
	*(u32 *)(fp + 24) |= 0x80000000U;
	CHECK(pt(SETFP, 0, fp) == -EINVAL, 2);
	CHECK(pt(GETFP, 0, xs) == 0 && (*(u32 *)(xs + 24) & 0x80000000U) == 0,
	    3);
	return finish(0);
}
static int
gpr_read(void)
{
	struct regs r;
	int e = start(0);
	if (e)
		return e;
	CHECK(pt(GETREGS, 0, &r) == 0, 1);
	CHECK(r.r12 == 0x1234 && r.fsbase == 0x12345000 &&
		r.gsbase == 0x23456000,
	    2);
	return finish(0);
}
static int
gpr_write(void)
{
	struct regs r;
	int e = start(2);
	if (e)
		return e;
	CHECK(pt(GETREGS, 0, &r) == 0, 1);
	r.r12 = 0x5678;
	CHECK(regset(SETSET, PRSTATUS, &r, sizeof(r)) == 0, 2);
	CHECK(pt(GETREGS, 0, &r) == 0 && r.r12 == 0x5678, 3);
	return finish(0);
}
static int
gpr_partial(void)
{
	struct regs r;
	int e = start(2);
	if (e)
		return e;
	CHECK(pt(GETREGS, 0, &r) == 0, 1);
	r.r12 = 0x5678;
	CHECK(regset(SETSET, PRSTATUS, &r, 32) == 0, 2);
	return finish(0);
}
static int
gpr_rax(void)
{
	struct regs r;
	int e = start(0);
	if (e)
		return e;
	CHECK(pt(GETREGS, 0, &r) == 0, 1);
	r.rax = 0x7788;
	CHECK(pt(SETREGS, 0, &r) == 0, 2);
	CHECK(pt(GETREGS, 0, &r) == 0 && r.rax == 0x7788, 3);
	return finish(0);
}
static int
gpr_bad_base(void)
{
	struct regs r;
	int e = start(0);
	if (e)
		return e;
	CHECK(pt(GETREGS, 0, &r) == 0, 1);
	r.fsbase = ~0UL;
	CHECK(regset(SETSET, PRSTATUS, &r, sizeof(r)) == -EIO, 2);
	CHECK(pt(GETREGS, 0, &r) == 0 && r.fsbase == 0x12345000, 3);
	return finish(0);
}
static int
lengths(void)
{
	int e = start(0);
	if (e)
		return e;
	int notes[] = { PRSTATUS, FPREG, XSTATE };
	for (int i = 0; i < 3; i++) {
		struct vec v = { xs, sizeof(xs) };
		CHECK(regset(GETSET, notes[i], xs, 7) == -EINVAL, 1 + i);
		CHECK(regset(GETSET, notes[i], (void *)1, 0) == 0, 4 + i);
		CHECK(pt(GETSET, notes[i], &v) == 0 && v.len > 0 &&
			v.len <= sizeof(xs),
		    7 + i);
		CHECK(regset(GETSET, notes[i], xs, 8) == 0, 10 + i);
	}
	CHECK(regset(SETSET, FPREG, (void *)1, 0) == -EINVAL, 14);
	return finish(0);
}
static int
faults(void)
{
	int e = start(0);
	if (e)
		return e;
	CHECK(pt(GETFP, 0, (void *)1) == -EFAULT, 1);
	CHECK(pt(SETFP, 0, (void *)1) == -EFAULT, 2);
	CHECK(pt(GETSET, FPREG, (void *)1) == -EFAULT, 3);
	CHECK(regset(GETSET, FPREG, (void *)1, 512) == -EFAULT, 4);
	CHECK(regset(SETSET, PRSTATUS, (void *)1, 216) == -EFAULT, 5);
	return finish(0);
}
static int
unknown(void)
{
	int e = start(0);
	if (e)
		return e;
	CHECK(regset(GETSET, 0x555, xs, 512) == -EINVAL, 1);
	CHECK(regset(SETSET, 0x555, xs, 512) == -EINVAL, 2);
	return finish(0);
}
static int
xstate_read(void)
{
	int e = start(0);
	if (e)
		return e;
	struct vec v = { xs, sizeof(xs) };
	CHECK(pt(GETSET, XSTATE, &v) == 0, 1);
	CHECK(v.len >= 576 && xs[160] == 255 && (*(u64 *)(xs + 464) & 3) == 3,
	    2);
	CHECK(*(u64 *)(xs + 520) == 0, 3);
	if (has_avx()) {
		CHECK(v.len >= 832 && (*(u64 *)(xs + 464) & 4) != 0, 5);
		for (int i = 592; i < 608; i++)
			CHECK(xs[i] == 255, 6);
	}
	for (int i = 528; i < 576; i++)
		CHECK(xs[i] == 0, 4);
	return finish(0);
}
static int
access(void)
{
	child = sys0(SYS_getpid);
	CHECK(pt(GETFP, 0, fp) == -ESRCH, 1);
	return 0;
}
static int
protected_memory(void)
{
	int e = start(0);
	if (e)
		return e;
	long m = sys6(SYS_mmap, 0, 8192, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(m > 0, 1);
	CHECK(sys3(SYS_mprotect, m + 4096, 4096, PROT_NONE) == 0, 2);
	CHECK(regset(GETSET, FPREG, (void *)(m + 4096 - 256), 512) == -EFAULT,
	    3);
	CHECK(pt(SETFP, 0, (void *)(m + 4096 - 256)) == -EFAULT, 4);
	CHECK(sys3(SYS_mprotect, m, 4096, PROT_READ) == 0, 5);
	CHECK(regset(GETSET, FPREG, (void *)m, 512) == -EFAULT, 6);
	CHECK(sys2(SYS_munmap, m, 8192) == 0, 7);
	return finish(0);
}
static int
bounds(void)
{
	int e = start(0);
	if (e)
		return e;
	struct vec v = { xs, 1024 };
	xmemset(xs, 0xa5, sizeof(xs));
	CHECK(pt(GETSET, FPREG, &v) == 0 && v.len == 512, 1);
	for (int i = 512; i < 1024; i++)
		CHECK(xs[i] == 0xa5, 2);
	v.len = 8;
	xmemset(xs, 0xa5, 512);
	CHECK(pt(GETSET, FPREG, &v) == 0 && v.len == 8, 3);
	for (int i = 8; i < 512; i++)
		CHECK(xs[i] == 0xa5, 4);
	return finish(0);
}
static int
permissions(void)
{
	long save = child;
	child = sys0(SYS_getpid);
	long rc = pt(GETFP, 0, fp);
	child = save;
	if (rc != -ESRCH)
		return 1;
	child = 99999999;
	if (pt(GETFP, 0, fp) != -ESRCH)
		return 2;
	return 0;
}
static int
unprivileged(void)
{
	long p = fork_process();
	int st;
	if (p < 0)
		return 1;
	if (p == 0) {
		if (sys0(102) == 0 &&
		    (sys1(106, 60001) != 0 || sys1(105, 60001) != 0))
			sys1(SYS_exit, 2);
		char *av[] = { self_path, "fp_write", 0 };
		char *ev[] = { 0 };
		sys3(SYS_execve, self_path, av, ev);
		sys1(SYS_exit, 5);
		for (;;) {
		}
	}
	if (sys4(SYS_wait4, p, &st, 0, 0) != p)
		return 3;
	return st == 0 ? 0 : 4;
}
static int
gpr_fault_progress(void)
{
	int e = start(0);
	if (e)
		return e;
	struct regs r;
	long m = sys6(SYS_mmap, 0, 8192, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(m > 0, 1);
	CHECK(sys3(SYS_mprotect, m + 4096, 4096, PROT_NONE) == 0, 2);
	*(u64 *)(m + 4096 - 8) = 0x8899;
	CHECK(regset(SETSET, PRSTATUS, (void *)(m + 4096 - 8), 16) == -EFAULT,
	    3);
	CHECK(pt(GETREGS, 0, &r) == 0 && r.r15 == 0x8899, 4);
	sys2(SYS_munmap, m, 8192);
	return finish(0);
}
static int
tls_write(void)
{
	int e = start(0);
	if (e)
		return e;
	struct regs r;
	CHECK(pt(GETREGS, 0, &r) == 0, 1);
	r.fsbase = 0x34567000;
	r.gsbase = 0x45678000;
	CHECK(regset(SETSET, PRSTATUS, &r, sizeof(r)) == 0, 2);
	CHECK(pt(GETREGS, 0, &r) == 0 && r.fsbase == 0x34567000 &&
		r.gsbase == 0x45678000,
	    3);
	return finish(0);
}
static int thread_pipe[2], thread_block[2];
static int
trace_worker(void *unused)
{
	long tid = sys0(SYS_gettid);
	char byte;
	(void)unused;
	if (sys2(158, 0x1002, 0x67890000) != 0)
		return 1;
	__asm__ volatile("pcmpeqd %%xmm0,%%xmm0" ::: "xmm0");
	sys3(SYS_write, thread_pipe[1], &tid, sizeof(tid));
	sys3(SYS_read, thread_block[0], &byte, 1);
	return 0;
}
static int
thread_target(void)
{
	long pid, tid;
	int st, rc = 0;
	struct regs regs;
	struct thread worker;
	if (sys1(SYS_pipe, thread_pipe) != 0 ||
	    sys1(SYS_pipe, thread_block) != 0)
		return 1;
	pid = fork_process();
	if (pid < 0)
		return 2;
	if (pid == 0) {
		if (thread_create(&worker, trace_worker, 0) < 0)
			sys1(SYS_exit_group, 3);
		thread_join(&worker);
		sys1(SYS_exit_group, 0);
		for (;;) {
		}
	}
	if (sys3(SYS_read, thread_pipe[0], &tid, sizeof(tid)) != sizeof(tid)) {
		rc = 4;
		goto out;
	}
	child = tid;
	if (pt(16, 0, 0) != 0) {
		rc = 5;
		goto out;
	}
	if (sys4(SYS_wait4, -1, &st, 0x40000000, 0) < 0 || (st & 255) != 127) {
		rc = 6;
		goto out;
	}
	if (pt(GETREGS, 0, &regs) != 0 || regs.fsbase != 0x67890000)
		rc = 7;
	if (pt(GETFP, 0, fp) != 0 || fp[160] != 255)
		rc = 8;
	if (pt(17, 0, 0) != 0)
		rc = 9;
out:
	sys2(SYS_kill, pid, SIGKILL);
	while (sys4(SYS_wait4, -1, &st, 0x40000000, 0) > 0) {
	}
	for (int i = 0; i < 2; i++) {
		sys1(SYS_close, thread_pipe[i]);
		sys1(SYS_close, thread_block[i]);
	}
	return rc;
}

static int
repeated(void)
{
	for (int i = 0; i < 32; i++) {
		int e = fp_setregset();
		if (e)
			return e;
	}
	return 0;
}
static int
no_xsave(void)
{
	int e = start(0);
	if (e)
		return e;
	CHECK(regset(GETSET, XSTATE, xs, sizeof(xs)) == -ENODEV, 1);
	CHECK(pt(GETFP, 0, fp) == 0, 2);
	return finish(0);
}
static int
test(int argc, char **argv, char **envp)
{
	(void)envp;
	(void)change;
	(void)access;
	self_path = argv[0];
	if (argc == 2 && xstreq(argv[1], "no_xsave"))
		return no_xsave();
	static const struct subtest cases[] = { { "fp_read", fp_read },
		{ "fp_write", fp_write }, { "fp_setregset", fp_setregset },
		{ "fp_bad_mxcsr", fp_bad_mxcsr }, { "gpr_read", gpr_read },
		{ "gpr_write", gpr_write }, { "gpr_partial", gpr_partial },
		{ "gpr_rax", gpr_rax }, { "gpr_bad_base", gpr_bad_base },
		{ "lengths", lengths }, { "faults", faults },
		{ "unknown", unknown }, { "xstate_read", xstate_read },
		{ "protected_memory", protected_memory }, { "bounds", bounds },
		{ "permissions", permissions },
		{ "unprivileged", unprivileged },
		{ "gpr_fault_progress", gpr_fault_progress },
		{ "tls_write", tls_write }, { "thread_target", thread_target },
		{ "repeated", repeated } };
	return run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0]));
}
