/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * bsdtrace_ptwrite.h - PTWRITE intrinsic for user-space trace markers.
 *
 * Include this header in programs traced with bsdtrace -W to emit
 * user-directed trace markers into the Intel PT stream.  The markers
 * are emitted as PTW packets carrying the payload value you supply.
 *
 * Usage:
 *   #include "bsdtrace_ptwrite.h"
 *
 *   bsdtrace_ptwrite(42);           // 64-bit marker
 *   bsdtrace_ptwrite(state_id);     // tag a state transition
 *   bsdtrace_ptwrite(0xDEAD);       // sentinel value
 *
 * Requirements:
 *   - CPU must support PTWRITE (CPUID leaf 0x14 EBX bit 4)
 *   - The process must be actively traced with bsdtrace -W
 *     (which sets RTIT_CTL_PTWEN in the kernel)
 *   - If EITHER condition is not met, the instruction raises #UD
 *     (SIGILL).  bsdtrace_has_ptwrite() only checks CPU support,
 *     not whether tracing is active.  In practice, always use
 *     PTWRITE from code you know will be traced with -W.
 */

#ifndef _BSDTRACE_PTWRITE_H_
#define _BSDTRACE_PTWRITE_H_

#if !defined(__x86_64__)
#error "bsdtrace_ptwrite.h requires x86_64 (Intel PT PTWRITE instruction)"
#endif

#include <stdint.h>

/*
 * Emit a PTWRITE trace marker (64-bit payload).
 *
 * Uses the REX.W form so the full 64-bit value is written to the
 * PT stream.  With FUPONPTW enabled (always set by bsdtrace -W),
 * the hardware also emits a FUP so the decoder knows the IP context.
 *
 * The "memory" clobber ensures the compiler does not reorder
 * surrounding memory operations across this marker.
 */
static inline void
bsdtrace_ptwrite(uint64_t val)
{
	__asm__ __volatile__(
	    ".byte 0xf3,0x48,0x0f,0xae,0xe0"  /* ptwrite %rax (F3 REX.W 0F AE /4) */
	    : : "a"(val) : "memory");
}

/*
 * Emit a PTWRITE trace marker (32-bit payload).
 *
 * Slightly smaller encoding than the 64-bit form.  Use when the
 * payload fits in 32 bits.
 */
static inline void
bsdtrace_ptwrite32(uint32_t val)
{
	__asm__ __volatile__(
	    ".byte 0xf3,0x0f,0xae,0xe0"  /* ptwrite %eax (F3 0F AE /4) */
	    : : "a"(val) : "memory");
}

/*
 * Check whether the CPU supports PTWRITE (CPUID leaf 0x14, EBX bit 4).
 *
 * This checks hardware capability only.  PTWRITE will still #UD if
 * the process is not being traced with PTWEN enabled (bsdtrace -W).
 */
static inline int
bsdtrace_has_ptwrite(void)
{
	uint32_t eax, ebx, ecx, edx;

	__asm__ __volatile__("cpuid"
	    : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
	    : "a"(0x14), "c"(0));
	return ((ebx >> 4) & 1);
}

#endif /* !_BSDTRACE_PTWRITE_H_ */
