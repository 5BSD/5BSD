#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production guest user-stack helpers on three frame layouts."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static int\ndtrace_guest_trapframe(')
end_start = source.index('static uint64_t\ndtrace_guest_ucaller(', start)
depth_start = source.index('static uint64_t\ndtrace_guest_ustackdepth(', end_start)
stack_start = source.index('static void\ndtrace_guest_getupcstack(', depth_start)
end = source.index('\n}', stack_start) + 2
helper = source[start:end]
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/hypertrace.h>
/* A failed ASSERT is a debug-kernel panic: trap it where a case expects one. */
static jmp_buf assert_trap;
static int assert_armed;
#define ASSERT(x) do { if (!(x)) { assert(assert_armed); \
    longjmp(assert_trap, 1); } } while (0)
#define ASSERT_TRIPS(stmt) do { assert_armed = 1; \
    if (setjmp(assert_trap) == 0) { stmt; assert(!"ASSERT held"); } \
    assert_armed = 0; } while (0)
#undef __amd64__
#undef __aarch64__
#undef __riscv
#if defined(TEST_AMD64)
#define __amd64__ 1
#elif defined(TEST_ARM64)
#define __aarch64__ 1
#else
#define __riscv 1
#endif
typedef unsigned int uint_t;
enum { CPU_DTRACE_ILLOP = 1, CPU_DTRACE_BADADDR = 2,
    CPU_DTRACE_ENTRY = 4, CPU_DTRACE_BADSTACK = 8,
    CPU_DTRACE_FAULT = 3 };
struct trapframe {
    uint64_t tf_rip, tf_rbp, tf_rsp, tf_elr, tf_x[30], tf_lr;
    uint64_t tf_sepc, tf_s[12], tf_ra;
};
struct thread { uint8_t padding[24]; struct trapframe *td_frame; };
typedef struct { hypertrace_args_t *dtms_htrargs;
    const void *dtms_vmhdl; } dtrace_mstate_t;
static struct { unsigned cpuc_dtrace_flags; uintptr_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0;
#define DTRACE_CPUFLAG_SET(flag) (cpu_core[curcpu].cpuc_dtrace_flags |= (flag))
#define DTRACE_CPUFLAG_ISSET(flag) ((cpu_core[curcpu].cpuc_dtrace_flags & (flag)) != 0)
static uint8_t guest_mem[0x4000];
static const int guest_handle = 1;
static int user_reads, kernel_reads, user_error;
static uint64_t expected_addr, return_pc;
static uint64_t depth_addrs[5], depth_words[5];
static int guest_copy(const void *h, uint64_t addr, void *dst, size_t len)
{
    assert(h == &guest_handle && len != 0);
    kernel_reads++;
    if (addr > sizeof(guest_mem) || len > sizeof(guest_mem) - addr)
        return EFAULT;
    memcpy(dst, guest_mem + addr, len);
    return 0;
}
static int user_copy(const void *h, uint64_t addr, void *dst, size_t len)
{
    assert(h == &guest_handle && len == sizeof(uint64_t));
    user_reads++;
    if (user_error != 0)
        return user_error;
    assert(addr == expected_addr);
    memcpy(dst, &return_pc, len);
    return 0;
}
static int depth_copy(const void *h, uint64_t addr, void *dst, size_t len)
{
    assert(h == &guest_handle && len == sizeof(uint64_t));
    user_reads++;
    if (user_error != 0)
        return user_error;
    for (size_t i = 0; i < 5; i++) {
        if (addr == depth_addrs[i]) {
            memcpy(dst, &depth_words[i], len);
            return 0;
        }
    }
    return EFAULT;
}
int (*hypertrace_guest_copyin)(const void *, uint64_t, void *, size_t)
    = guest_copy;
int (*hypertrace_guest_user_copyin)(const void *, uint64_t, void *, size_t)
    = user_copy;
static uint64_t dtrace_getreg(struct trapframe *frame, uint_t ndx)
{
    (void)ndx;
    return frame->tf_rip;
}
HELPER
static void reset(void)
{
    cpu_core[0].cpuc_dtrace_flags = 0;
    cpu_core[0].cpuc_dtrace_illval = 0;
    user_reads = 0;
    kernel_reads = 0;
    user_error = 0;
    hypertrace_guest_user_copyin = user_copy;
}
int main(void)
{
    const uintptr_t thread_addr = 0x1000, frame_addr = 0x2000;
    struct trapframe frame = { 0 };
    hypertrace_args_t args = { .htr_curthread = (void *)thread_addr,
        .htr_pid = 77 };
    dtrace_mstate_t state = { &args, &guest_handle };
    const uint64_t fp = 0x3000;
    uint64_t value;
    memcpy(guest_mem + thread_addr + offsetof(struct thread, td_frame),
        &frame_addr, sizeof(frame_addr));
#if defined(TEST_AMD64)
    frame.tf_rip = 0x1111; frame.tf_rbp = fp; frame.tf_rsp = 0x3100;
    expected_addr = fp + 8;
#elif defined(TEST_ARM64)
    frame.tf_elr = 0x1111; frame.tf_x[29] = fp; frame.tf_lr = 0x3333;
    expected_addr = fp + 8;
#else
    frame.tf_sepc = 0x1111; frame.tf_s[0] = fp; frame.tf_ra = 0x3333;
    expected_addr = fp - 8;
#endif
    memcpy(guest_mem + frame_addr, &frame, sizeof(frame));
    return_pc = 0x2222;
    reset();
    assert(dtrace_guest_ureg(&state, 0, &value) == 1 &&
        value == frame.tf_rip);
    value = dtrace_guest_ucaller(&state);
    assert(value == return_pc && user_reads == 1 &&
        cpu_core[0].cpuc_dtrace_flags == 0);
    reset(); args.htr_pid = 0;
    assert(dtrace_guest_ucaller(&state) == 0 && user_reads == 0 &&
        kernel_reads == 0 && cpu_core[0].cpuc_dtrace_flags == 0);
    args.htr_pid = 77;
    reset(); user_error = EFAULT;
    assert(dtrace_guest_ucaller(&state) == 0 && user_reads == 1 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        cpu_core[0].cpuc_dtrace_illval == expected_addr);
    reset(); user_error = EOPNOTSUPP;
    assert(dtrace_guest_ucaller(&state) == 0 && user_reads == 1 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP);
    reset(); hypertrace_guest_user_copyin = NULL;
    assert(dtrace_guest_ucaller(&state) == 0 && user_reads == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP);
    reset(); args.htr_entry = 1;
#if defined(TEST_AMD64)
    expected_addr = frame.tf_rsp;
    assert(dtrace_guest_ucaller(&state) == return_pc && user_reads == 1);
#elif defined(TEST_ARM64)
    assert(dtrace_guest_ucaller(&state) == frame.tf_lr && user_reads == 0);
#else
    assert(dtrace_guest_ucaller(&state) == frame.tf_ra && user_reads == 0);
#endif
    reset(); args.htr_entry = 0;
#if defined(TEST_AMD64)
    frame.tf_rip = 0;
#elif defined(TEST_ARM64)
    frame.tf_elr = 0;
#else
    frame.tf_sepc = 0;
#endif
    memcpy(guest_mem + frame_addr, &frame, sizeof(frame));
    assert(dtrace_guest_ucaller(&state) == 0 && user_reads == 0 &&
        cpu_core[0].cpuc_dtrace_flags == 0);
    reset(); args.htr_entry = 2;
    assert(dtrace_guest_ucaller(&state) == 0 && user_reads == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP);
    args.htr_entry = 0;
    /* DIF emulation stops at the first fault. */
    reset(); DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
    ASSERT_TRIPS(dtrace_guest_ucaller(&state));
    assert(user_reads == 0 && kernel_reads == 0);
    reset(); DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
    ASSERT_TRIPS(dtrace_guest_ustackdepth(&state));
    assert(user_reads == 0 && kernel_reads == 0);
    reset(); state.dtms_htrargs = NULL;
    assert(dtrace_guest_ucaller(&state) == 0 && user_reads == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP);
    state.dtms_htrargs = &args;
#if defined(TEST_AMD64)
    frame.tf_rip = 0x1111;
    depth_addrs[0] = fp + 8; depth_addrs[1] = fp;
    depth_addrs[2] = 0x3408; depth_addrs[3] = 0x3400;
    depth_addrs[4] = frame.tf_rsp;
#elif defined(TEST_ARM64)
    frame.tf_elr = 0x1111;
    depth_addrs[0] = fp + 8; depth_addrs[1] = fp;
    depth_addrs[2] = 0x3408; depth_addrs[3] = 0x3400;
#else
    frame.tf_sepc = 0x1111;
    depth_addrs[0] = fp - 8; depth_addrs[1] = fp - 16;
    depth_addrs[2] = 0x3400 - 8; depth_addrs[3] = 0x3400 - 16;
#endif
    depth_words[0] = 0x2222; depth_words[1] = 0x3400;
    depth_words[2] = 0; depth_words[3] = 0;
    depth_words[4] = 0x4444;
    memcpy(guest_mem + frame_addr, &frame, sizeof(frame));
    reset(); hypertrace_guest_user_copyin = depth_copy;
    assert(dtrace_guest_ustackdepth(&state) == 2 && user_reads == 4 &&
        cpu_core[0].cpuc_dtrace_flags == 0);
    reset(); args.htr_pid = 0;
    assert(dtrace_guest_ustackdepth(&state) == 0 && user_reads == 0 &&
        kernel_reads == 0 && cpu_core[0].cpuc_dtrace_flags == 0);
    args.htr_pid = 77;
    reset(); hypertrace_guest_user_copyin = depth_copy;
    args.htr_entry = 1;
    assert(dtrace_guest_ustackdepth(&state) == 3 &&
#if defined(TEST_AMD64)
        user_reads == 5 &&
#else
        user_reads == 4 &&
#endif
        cpu_core[0].cpuc_dtrace_flags == 0);
    args.htr_entry = 0;
    reset(); hypertrace_guest_user_copyin = depth_copy;
    depth_words[1] = fp;
    assert(dtrace_guest_ustackdepth(&state) == 1 && user_reads == 2 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADSTACK &&
        cpu_core[0].cpuc_dtrace_illval == fp);
    depth_words[1] = 0x3400;
    reset(); hypertrace_guest_user_copyin = depth_copy;
    user_error = EFAULT;
    assert(dtrace_guest_ustackdepth(&state) == 0 && user_reads == 1 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        cpu_core[0].cpuc_dtrace_illval == depth_addrs[0]);
    reset(); hypertrace_guest_user_copyin = NULL;
    assert(dtrace_guest_ustackdepth(&state) == 0 && user_reads == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP);
    reset(); args.htr_entry = 2;
    assert(dtrace_guest_ustackdepth(&state) == 0 && user_reads == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP);
    uint64_t stack[6];
    args.htr_entry = 0;
    args.htr_pid = 77;
    reset(); hypertrace_guest_user_copyin = depth_copy;
    memset(stack, 0xa5, sizeof(stack));
    dtrace_guest_getupcstack(&state, 7, stack, 6);
    assert(stack[0] == HYPERTRACE_USTACK_ENCODE(7, 77) &&
        HYPERTRACE_USTACK_GUEST(stack[0]) &&
        HYPERTRACE_USTACK_VMID(stack[0]) == 7 &&
        HYPERTRACE_USTACK_PID(stack[0]) == 77 && stack[1] == 0x1111 &&
        stack[2] == 0x2222 && stack[3] == 0 && stack[4] == 0 &&
        stack[5] == 0 && user_reads == 4 &&
        cpu_core[0].cpuc_dtrace_flags == 0);
    reset(); args.htr_pid = 0;
    memset(stack, 0xa5, sizeof(stack));
    dtrace_guest_getupcstack(&state, 7, stack, 6);
    for (size_t i = 0; i < 6; i++) assert(stack[i] == 0);
    assert(user_reads == 0 && kernel_reads == 0 &&
        cpu_core[0].cpuc_dtrace_flags == 0);
    args.htr_pid = 77;
    args.htr_entry = 1;
    reset(); hypertrace_guest_user_copyin = depth_copy;
    memset(stack, 0xa5, sizeof(stack));
    dtrace_guest_getupcstack(&state, 7, stack, 6);
    assert(stack[0] == HYPERTRACE_USTACK_ENCODE(7, 77) &&
        stack[1] == 0x1111 &&
#if defined(TEST_AMD64)
        stack[2] == 0x4444 && user_reads == 5 &&
#else
        stack[2] == 0x3333 && user_reads == 4 &&
#endif
        stack[3] == 0x2222 && stack[4] == 0 && stack[5] == 0 &&
        cpu_core[0].cpuc_dtrace_flags == 0);
    args.htr_entry = 0;
    reset(); hypertrace_guest_user_copyin = depth_copy;
    user_error = EFAULT;
    dtrace_guest_getupcstack(&state, 7, stack, 6);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        cpu_core[0].cpuc_dtrace_illval == depth_addrs[0]);
    reset(); hypertrace_guest_user_copyin = depth_copy;
    depth_words[1] = fp;
    dtrace_guest_getupcstack(&state, 7, stack, 6);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADSTACK &&
        cpu_core[0].cpuc_dtrace_illval == fp);
    depth_words[1] = 0x3400;
    reset(); hypertrace_guest_user_copyin = NULL;
    dtrace_guest_getupcstack(&state, 7, stack, 6);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP);
    reset();
    dtrace_guest_getupcstack(&state, 0, stack, 6);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        user_reads == 0);
    args.htr_entry = 2;
    reset();
    dtrace_guest_getupcstack(&state, 7, stack, 6);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        stack[0] == 0 && stack[1] == 0);
    puts("PASS: production guest user caller, depth, and stack action paths");
    return 0;
}
'''.replace('HELPER', helper)
path = out / 'guest-ucaller.c'
path.write_text(fixture)
for arch in ('AMD64', 'ARM64', 'RISCV'):
    binary = out / f'guest-ucaller-{arch.lower()}'
    subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
        f'-DTEST_{arch}=1', str(path),
        '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
