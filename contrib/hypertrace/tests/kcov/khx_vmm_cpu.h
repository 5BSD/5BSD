/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Forced include for the amd64 VMM HyperTrace suite: route the privileged
 * instructions vm_run() executes around a guest entry (CR0.TS via clts and
 * load_cr0, CR4 and XCR0 reads/writes) to a harness model, so the run
 * loop's exit dispatch can execute in a user process.  The CPUID
 * instruction is routed too, so the suite can feed the guest's own
 * detector (bhyve_hypercalls_enabled() in machine/bhyve_hypercall.h) from
 * the VMM's CPUID emulation.  Production source text is unchanged.
 */
#ifndef KHX_VMM_CPU_H
#define KHX_VMM_CPU_H
/*
 * The VMM's vCPU locks are spin mutexes (MTX_SPIN), which the shared
 * harness mutex does not model.  Route mtx_init() through khx_vmm.c, which
 * initializes them as harness mutexes; mtx_lock_spin()/mtx_unlock_spin()
 * add the critical section (khx_vmm.c).
 */
#define _mtx_init khx_vmm_mtx_init
#include <sys/cdefs.h>
#include <sys/types.h>
#define do_cpuid khx_hw_do_cpuid
#define clts khx_hw_clts
#define rcr0 khx_hw_rcr0
#define load_cr0 khx_hw_load_cr0
#define rcr4 khx_hw_rcr4
#define rxcr khx_hw_rxcr
#define load_xcr khx_hw_load_xcr
#include <machine/cpufunc.h>
#undef do_cpuid
#undef clts
#undef rcr0
#undef load_cr0
#undef rcr4
#undef rxcr
#undef load_xcr
void khx_do_cpuid(u_int ax, u_int *p);
void khx_clts(void);
u_long khx_rcr0(void);
void khx_load_cr0(u_long v);
u_long khx_rcr4(void);
u_long khx_rxcr(u_int reg);
void khx_load_xcr(u_int reg, u_long v);
#define do_cpuid(ax, p) khx_do_cpuid((ax), (p))
#define clts() khx_clts()
#define rcr0() khx_rcr0()
#define load_cr0(v) khx_load_cr0(v)
#define rcr4() khx_rcr4()
#define rxcr(r) khx_rxcr(r)
#define load_xcr(r, v) khx_load_xcr((r), (v))
#endif
