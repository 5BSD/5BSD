/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/cdefs.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_USTACK_DEPTH 2048
#define CPU_DTRACE_FAULT 1u
#define CPU_DTRACE_ENTRY 2u
#define CPU_DTRACE_BADSTACK 4u
#define CPU_DTRACE_ILLOP 8u
#define CPU_DTRACE_BADALIGN 16u
#define CPU_DTRACE_BADADDR 32u
#define ASSERT(test) assert(test)
#define DTRACE_CPUFLAG_ISSET(flag) ((cpu_core[curcpu].cpuc_dtrace_flags & (flag)) != 0)
#define DTRACE_CPUFLAG_SET(flag) (cpu_core[curcpu].cpuc_dtrace_flags |= (flag))

struct unwind_state { uintptr_t fp; uintptr_t pc; };
struct trapframe {
	uint64_t tf_elr, tf_x[31], tf_lr;
	uint64_t tf_sepc, tf_s[12], tf_ra, tf_a[8], tf_sp;
};
struct kdtrace_thread {
	struct trapframe *td_dtrace_trapframe;
};
struct thread {
	struct trapframe *td_frame;
	struct kdtrace_thread *td_dtrace;
};
#define t_dtrace_trapframe td_dtrace->td_dtrace_trapframe
typedef struct proc { int p_pid; } proc_t;
static proc_t *curproc;
static struct thread *curthread;
static int curcpu;
static struct {
	uint16_t cpuc_dtrace_flags;
	uintptr_t cpuc_dtrace_illval;
} cpu_core[1];
static uint64_t stack_args[2];
static struct dtrace_error_arg {
	uintptr_t illval;
	bool active;
} dtrace_error_arg[1];
static bool
kstack_contains(struct thread *td, uintptr_t p, size_t size)
{
	(void)td;
	return (p >= (uintptr_t)stack_args && size <= sizeof(stack_args) &&
	    p - (uintptr_t)stack_args <= sizeof(stack_args) - size);
}
static uint64_t
dtrace_fuword64(void *address)
{
	return (*(uint64_t *)address);
}

#if TEST_ARM64
#include "provider-userstack-aarch64.inc"
#else
#include "provider-userstack-riscv.inc"
#endif

int
main(void)
{
	proc_t process = {.p_pid = 123};
	struct trapframe tf = {};
	struct kdtrace_thread dtrace_thread = {.td_dtrace_trapframe = &tf};
	struct thread thread = {.td_frame = &tf, .td_dtrace = &dtrace_thread};
	uint64_t frame2[2] = {0, 0x300};
	uint64_t frame1[2];
	uint64_t pcstack[5], fpstack[4];
	uintptr_t fp1, fp2;
	curproc = &process;
	curthread = &thread;
	curcpu = 0;
#if TEST_ARM64
	fp2 = (uintptr_t)frame2;
	frame1[0] = fp2;
	frame1[1] = 0x200;
	fp1 = (uintptr_t)frame1;
	tf.tf_elr = 0x100;
	tf.tf_x[29] = fp1;
	tf.tf_lr = 0x200;
	tf.tf_x[0] = 0x71;
#else
	fp2 = (uintptr_t)(frame2 + 2);
	frame1[0] = fp2;
	frame1[1] = 0x200;
	fp1 = (uintptr_t)(frame1 + 2);
	tf.tf_sepc = 0x100;
	tf.tf_s[0] = fp1;
	tf.tf_ra = 0x200;
	tf.tf_a[0] = 0x71;
#endif
	memset(pcstack, 0xa5, sizeof(pcstack));
	memset(fpstack, 0xa5, sizeof(fpstack));
	dtrace_getufpstack(pcstack, fpstack, 5);
	assert(pcstack[0] == 123 && pcstack[1] == 0x100 &&
	    pcstack[2] == 0x200 && pcstack[3] == 0x300 && pcstack[4] == 0);
	assert(fpstack[0] == fp1 && fpstack[1] == fp2 && fpstack[2] == 0);
	assert(dtrace_getustackdepth() == 3);
	frame1[0] = fp1;
	memset(pcstack, 0xa5, sizeof(pcstack));
	dtrace_getufpstack(pcstack, fpstack, 5);
	assert(pcstack[0] == 123 && pcstack[1] == 0x100 &&
	    pcstack[2] == 0);
	assert(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_BADSTACK));
	assert(cpu_core[0].cpuc_dtrace_illval == fp1);
	frame1[0] = fp2;
	cpu_core[0].cpuc_dtrace_flags = 0;

	cpu_core[0].cpuc_dtrace_flags = CPU_DTRACE_ENTRY;
#if TEST_ARM64
	tf.tf_x[29] = fp2;
#else
	tf.tf_s[0] = fp2;
#endif
	memset(pcstack, 0xa5, sizeof(pcstack));
	dtrace_getufpstack(pcstack, fpstack, 5);
	assert(pcstack[0] == 123 && pcstack[1] == 0x100 &&
	    pcstack[2] == 0x200 && pcstack[3] == 0x300 &&
	    fpstack[0] == 0 && fpstack[1] == fp2);
	assert(dtrace_getustackdepth() == 3);
	cpu_core[0].cpuc_dtrace_flags = 0;
#if TEST_ARM64
	tf.tf_x[29] = fp1;
#else
	tf.tf_s[0] = fp1;
#endif

	curproc = NULL;
	memset(pcstack, 0xa5, sizeof(pcstack));
	dtrace_getufpstack(pcstack, fpstack, 5);
	for (size_t i = 0; i < 5; i++)
		assert(pcstack[i] == 0);
	curproc = &process;

	stack_args[0] = 0x81;
	stack_args[1] = 0x82;
	tf.tf_sp = (uintptr_t)stack_args;
	assert(dtrace_getarg(0, 0) == 0x71);
	/* The ERROR probe's sixth argument bypasses the trapframe. */
#if TEST_ARM64
	tf.tf_x[5] = 0x75;
#else
	tf.tf_a[5] = 0x75;
#endif
	assert(dtrace_getarg(5, 0) == 0x75);
	dtrace_error_arg[0].illval = 0xbad;
	dtrace_error_arg[0].active = true;
	assert(dtrace_getarg(5, 0) == 0xbad && dtrace_getarg(0, 0) == 0x71);
	dtrace_error_arg[0].active = false;
	assert(dtrace_getarg(5, 0) == 0x75);
	assert(dtrace_getarg(8, 0) == 0x81);
	assert(dtrace_getarg(9, 0) == 0x82);
	assert(dtrace_getarg(-1, 0) == 0);
	assert(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ILLOP));
	cpu_core[0].cpuc_dtrace_flags = 0;
	assert(dtrace_getarg(10, 0) == 0);
	assert(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_BADADDR));
	cpu_core[0].cpuc_dtrace_flags = 0;
	thread.t_dtrace_trapframe = NULL;
	assert(dtrace_getarg(0, 0) == 0);
	assert(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ILLOP));
	puts(TEST_ARM64 ? "PASS: arm64 user stacks and arguments" :
	    "PASS: RISC-V user stacks, depth and arguments");
}
