/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Test seam for bhyvectl_machdep.c: the inline CPUID instruction is replaced
 * by bhyve_cov_do_cpuid() so the vendor-specific (Intel VMCS / AMD VMCB)
 * paths of the original source can both run on one host.  The source's
 * function bodies are unchanged; only the inline helper they call differs.
 */
#ifndef BHYVE_COV_CPUID_H
#define BHYVE_COV_CPUID_H
#include <sys/types.h>
#include <machine/cpufunc.h>
void bhyve_cov_do_cpuid(u_int ax, u_int *p);
#define do_cpuid bhyve_cov_do_cpuid
#endif
