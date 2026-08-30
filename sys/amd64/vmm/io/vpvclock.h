/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Host-side KVM-compatible paravirtual clock (pvclock).
 *
 * This exposes the de-facto-standard KVM paravirtual clock ABI to the guest so
 * that the in-tree FreeBSD 'kvm_clock' driver (sys/dev/kvm_clock) and Linux's
 * 'kvm-clock' obtain an accurate, migration-aware time base.  The ABI (the
 * 'struct pvclock_vcpu_time_info' seqlock page, the mul/shift scaling and the
 * wall-clock structure) is described in <machine/pvclock.h> and the KVM MSR /
 * CPUID specification; nothing here is copied from GPL sources.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
 */

#ifndef _IO_VPVCLOCK_H_
#define	_IO_VPVCLOCK_H_

#include <sys/types.h>
#include <machine/pvclock.h>

/*
 * KVM paravirt-clock CPUID interface.  The signature leaf lives at the KVM
 * base (0x40000000) and the feature leaf immediately above it; the FreeBSD
 * guest 'kvm_clock' driver hard-codes these leaf numbers (see <x86/kvm.h>),
 * so they must not move.
 */
#define	VPVCLOCK_CPUID_KVM_BASE		0x40000000
#define	VPVCLOCK_CPUID_KVM_FEATURES	0x40000001

#define	VPVCLOCK_KVM_FEATURE_CLOCKSOURCE		0x00000001
#define	VPVCLOCK_KVM_FEATURE_CLOCKSOURCE2		0x00000008
#define	VPVCLOCK_KVM_FEATURE_MSI_EXT_DEST_ID		0x00008000
#define	VPVCLOCK_KVM_FEATURE_CLOCKSOURCE_STABLE_BIT	0x01000000

/*
 * KVM paravirt-clock MSRs.  The "NEW" pair goes with KVM_FEATURE_CLOCKSOURCE2
 * and is what current drivers use; the legacy 0x11/0x12 aliases go with
 * KVM_FEATURE_CLOCKSOURCE and are handled for completeness.
 */
#define	VPVCLOCK_MSR_WALL_CLOCK		0x11
#define	VPVCLOCK_MSR_SYSTEM_TIME	0x12
#define	VPVCLOCK_MSR_WALL_CLOCK_NEW	0x4b564d00
#define	VPVCLOCK_MSR_SYSTEM_TIME_NEW	0x4b564d01

/*
 * Pure ABI math and protocol helpers.  These are deliberately free of kernel
 * dependencies so that the model test (tests/sys/vmm/vpvclock_model_test.c)
 * exercises exactly the code the host runs.
 */

/*
 * Derive the pvclock (tsc_to_system_mul, tsc_shift) scaling pair for a virtual
 * TSC running at 'freq' Hz.  The guest computes nanoseconds from a TSC delta
 * as pvclock_scale_delta(delta, mul, shift), i.e.
 *
 *     ns = ((shift >= 0 ? delta << shift : delta >> -shift) * mul) >> 32
 *
 * which must approximate delta * 10^9 / freq.  Rearranging, we need
 *
 *     mul / 2^(32 - shift) == 10^9 / freq
 *
 * with 'mul' a 32-bit value whose top bit is set (maximal precision).  We
 * solve it in 64-bit arithmetic by keeping reduced copies of the numerator
 * (10^9) and denominator (freq), halving whichever term would otherwise
 * overflow a 32-bit intermediate and accumulating the net power of two into
 * 'shift'.  This is the standard fixed-point reciprocal used by every
 * pvclock host; it is implemented here from the ABI, not copied.
 */
static __inline void
vpvclock_freq_to_scale(uint64_t freq, uint32_t *mul, int8_t *shift)
{
	uint64_t num = 1000000000ULL;	/* nanoseconds per second */
	uint64_t den = (freq != 0) ? freq : 1;
	int s = 0;

	/*
	 * Reduce the denominator until it is smaller than twice the numerator
	 * and fits in 32 bits.  Every halving is a negative power of two.
	 */
	while (den > (num << 1) || (den >> 32) != 0) {
		den >>= 1;
		s--;
	}

	/*
	 * Now scale up until the (reduced) denominator strictly exceeds the
	 * numerator and the numerator still fits in 32 bits, so that the final
	 * quotient occupies the full 32-bit fraction.  Prefer growing the
	 * denominator, but halve the numerator when either value is about to
	 * overflow.
	 */
	while (den <= num || (num >> 32) != 0) {
		if ((num >> 32) != 0 || (den & 0x80000000ULL) != 0)
			num >>= 1;
		else
			den <<= 1;
		s++;
	}

	*mul = (uint32_t)((num << 32) / den);
	*shift = (int8_t)s;
}

/*
 * Publish a 'struct pvclock_vcpu_time_info' update using the pvclock version
 * seqlock discipline: the version is made odd before the payload is written
 * and even once the write is complete, so a concurrent guest reader (see
 * pvclock_read_time_info() in sys/x86/x86/pvclock.c) retries until it observes
 * a stable, even version.  'base_version' must be even; the returned value is
 * the new even version and must be fed back on the next update.
 *
 * Ordering is enforced with compiler barriers only: this path is amd64-only
 * where the hardware provides total store ordering, matching the guest's use
 * of acquire loads.  The structure is written little-endian and fixed-width
 * (amd64 is little-endian), satisfying the ABI's byte layout.
 */
static __inline uint32_t
vpvclock_fill_timeinfo(volatile struct pvclock_vcpu_time_info *ti,
    uint32_t base_version, uint64_t tsc_timestamp, uint64_t system_time,
    uint32_t mul, int8_t shift, uint8_t flags)
{
	uint32_t version = base_version + 1;	/* odd: update in progress */

	ti->version = version;
	__asm __volatile("" ::: "memory");

	ti->pad0 = 0;
	ti->tsc_timestamp = tsc_timestamp;
	ti->system_time = system_time;
	ti->tsc_to_system_mul = mul;
	ti->tsc_shift = shift;
	ti->flags = flags;
	ti->pad[0] = 0;
	ti->pad[1] = 0;
	__asm __volatile("" ::: "memory");

	version++;				/* even: update complete */
	ti->version = version;
	return (version);
}

#ifdef _KERNEL
struct vm;
struct vcpu;
struct vpvclock;

/* Per-VM lifecycle, wired from vmm.c alongside the other device models. */
struct vpvclock	*vpvclock_init(struct vm *vm);
void		 vpvclock_cleanup(struct vpvclock *pvc);

/*
 * MSR emulation entry points, called from the arch WRMSR/RDMSR paths
 * (vmx_msr.c and svm_msr.c).  They return 0 when the MSR belongs to the
 * pvclock device (and has been handled) or ENOENT otherwise, so the caller
 * can fall through to its default behaviour.
 *
 * These run inside the critical section vm_run() holds around guest entry,
 * so they only record state under a spin mutex; the guest-page writes are
 * deferred.  The arch run loops poll vpvclock_pending() before re-entering
 * the guest and bail out to vm_run(), which calls vpvclock_commit() outside
 * the critical section to map the guest page(s) and publish.
 */
int		 vpvclock_wrmsr(struct vcpu *vcpu, u_int msr, uint64_t val);
int		 vpvclock_rdmsr(struct vcpu *vcpu, u_int msr, uint64_t *val);

/*
 * Mark a vCPU's time-info page for republish (deferred, critical-section
 * safe).  Called on a guest TSC/TSC-offset change and on migration restore.
 */
void		 vpvclock_vcpu_update(struct vcpu *vcpu);

/*
 * Deferred-publish plumbing: vpvclock_pending() is the lock-free check the
 * arch run loops use before guest entry; vpvclock_commit() performs the
 * sleepable publish and must be called outside any critical section (from
 * vm_run() after critical_exit(), or from ioctl context with vCPUs frozen).
 */
bool		 vpvclock_pending(struct vcpu *vcpu);
void		 vpvclock_commit(struct vcpu *vcpu);

/*
 * Whether the KVM pvclock interface should be advertised/handled at all.
 * Controlled by the hw.vmm.pvclock.enabled tunable and gates both the CPUID
 * leaves (x86.c) and the MSR handlers so that, when disabled, guest-visible
 * behaviour is byte-for-byte the historical bhyve behaviour.
 */
bool		 vpvclock_capable(void);

/* KVM feature-leaf (0x40000001, %eax) bits to advertise. */
uint32_t	 vpvclock_kvm_features(void);
#endif /* _KERNEL */

#endif /* _IO_VPVCLOCK_H_ */
