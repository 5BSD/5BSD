/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Forced include for the DTrace suite: route the CPUID instruction used by
 * bhyve_hypercalls_enabled() to a harness model so guest-mode paths can be
 * exercised without a hypervisor.  Production source text is unchanged.
 */
#ifndef KHX_CPUID_H
#define KHX_CPUID_H
#include <sys/cdefs.h>
#include <sys/types.h>
#define do_cpuid khx_hw_do_cpuid
#include <machine/cpufunc.h>
#undef do_cpuid
void khx_do_cpuid(u_int ax, u_int *p);
#define do_cpuid(ax, p) khx_do_cpuid((ax), (p))
#endif
