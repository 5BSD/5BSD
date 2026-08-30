/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Host-side KVM-compatible paravirtual clock (pvclock).  See vpvclock.h for
 * an overview.  The interface is opt-in: the hw.vmm.pvclock.enabled tunable
 * defaults to off, so the historical bhyve-primary hypervisor identity is
 * preserved and no KVM signature is advertised unless an operator turns it on.
 * Even when advertised, no guest memory is touched until a guest opts in by
 * writing the KVM system-time MSR.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/clock.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>

#include <vm/vm.h>

#include <machine/clock.h>
#include <machine/cpufunc.h>
#include <machine/vmm.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_vm.h>

#include "vpvclock.h"

static MALLOC_DEFINE(M_VPVCLOCK, "vpvclock", "bhyve paravirtual clock");

/*
 * The KVM paravirtual clock is opt-in and defaults to off so the guest-visible
 * hypervisor identity stays exactly what historical bhyve presented: the bhyve
 * signature at leaf 0x40000000, no KVM leaves, and #GP on the KVM MSRs.  When an
 * operator sets this to 1, the KVM signature takes the primary hypervisor leaf
 * (0x40000000) and the guest sees vm_guest == VM_GUEST_KVM.  The bhyve
 * signature is still written to a secondary block (0x40000100), but a stock
 * guest does not discover it there: its hypervisor scan stops at the first
 * signature (KVM) and never reaches 0x40000100.  bhyve's EXT_DEST_ID capability
 * is instead preserved through the KVM feature bit KVM_FEATURE_MSI_EXT_DEST_ID.
 * The interface still stays inert until a guest writes the enable MSR.
 */
static int vpvclock_enabled = 0;
SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, pvclock, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "KVM-compatible paravirtual clock");
SYSCTL_INT(_hw_vmm_pvclock, OID_AUTO, enabled, CTLFLAG_RDTUN,
    &vpvclock_enabled, 0,
    "Advertise and service the KVM paravirtual clock interface");

/*
 * Locking / deferral contract
 * ---------------------------
 * The MSR handlers (vpvclock_rdmsr/wrmsr and the MSR_TSC hook
 * vpvclock_vcpu_update) run from the arch WRMSR/RDMSR emulation inside
 * vmmops_run, i.e. under the critical section vm_run() holds around guest
 * entry and with guest FPU state loaded.  They may therefore only take the
 * spin mutex below and may never map guest memory: mapping the time-info /
 * wall-clock pages goes through vm_slock_memsegs() (a sleepable sx lock) and
 * vm_gpa_hold_global(), both illegal under a critical section.
 *
 * The MSR paths only *record* the guest's request under the spin mutex and
 * raise a per-vCPU publish-pending flag; the arch run loops notice the flag
 * before the next guest entry and force a return to vm_run(), which calls
 * vpvclock_commit() after critical_exit() to perform the sleepable page
 * publish.  The deferred publish always lands before the vCPU re-enters guest
 * code, so the guest cannot observe the difference from an inline publish.
 *
 * Per-vCPU state (including the pending flags) is only written by the thread
 * emulating that vCPU, or from ioctl context while all vCPUs are frozen
 * (vm_restore_time), so unlocked reads of a vCPU's own state are stable on
 * those paths.  The spin mutex serialises cross-vCPU access to the shared
 * wall-clock fields and publication of the shared wall-clock page.
 */
struct vpvclock_vcpu {
	bool		system_time_enabled;	/* guest has enabled the page */
	bool		publish_pending;	/* time-info publish deferred */
	bool		wall_clock_pending;	/* wall-clock publish deferred */
	uint64_t	system_time_msr;	/* raw MSR value last written */
	uint64_t	system_time_gpa;	/* page-info GPA (enable stripped) */
	uint32_t	version;		/* last published (even) version */
};

struct vpvclock {
	struct mtx		 mtx;		/* MTX_SPIN; see above */
	struct vm		*vm;
	uint16_t		 maxcpus;
	/* Scaling derived from the virtual TSC frequency (see vpvclock.h). */
	uint32_t		 tsc_mul;
	int8_t			 tsc_shift;
	bool			 tsc_stable;
	/* Per-VM wall clock. */
	bool			 wall_clock_enabled;
	uint64_t		 wall_clock_gpa;
	uint32_t		 wall_clock_version;	/* last published (even) */
	struct vpvclock_vcpu	 vcpus[];
};

#define	VPVCLOCK_LOCK(pvc)	mtx_lock_spin(&(pvc)->mtx)
#define	VPVCLOCK_UNLOCK(pvc)	mtx_unlock_spin(&(pvc)->mtx)

bool
vpvclock_capable(void)
{
	return (vpvclock_enabled != 0 && tsc_freq != 0);
}

uint32_t
vpvclock_kvm_features(void)
{
	uint32_t features;

	features = VPVCLOCK_KVM_FEATURE_CLOCKSOURCE |
	    VPVCLOCK_KVM_FEATURE_CLOCKSOURCE2 |
	    VPVCLOCK_KVM_FEATURE_MSI_EXT_DEST_ID;

	/*
	 * Advertise the stable-TSC bit only when the host TSC is invariant and
	 * synchronised across physical CPUs, matching the "Invariant TSC"
	 * policy used for CPUID 8000_0007 in x86.c.  When set, the guest may
	 * skip its monotonicity backstop.
	 */
	if (tsc_is_invariant && smp_tsc)
		features |= VPVCLOCK_KVM_FEATURE_CLOCKSOURCE_STABLE_BIT;

	return (features);
}

struct vpvclock *
vpvclock_init(struct vm *vm)
{
	struct vpvclock *pvc;
	uint16_t maxcpus;

	maxcpus = vm_get_maxcpus(vm);
	pvc = malloc(sizeof(*pvc) + maxcpus * sizeof(struct vpvclock_vcpu),
	    M_VPVCLOCK, M_WAITOK | M_ZERO);
	pvc->vm = vm;
	pvc->maxcpus = maxcpus;
	vpvclock_freq_to_scale(tsc_freq, &pvc->tsc_mul, &pvc->tsc_shift);
	pvc->tsc_stable = (tsc_is_invariant && smp_tsc);
	mtx_init(&pvc->mtx, "vpvclock", NULL, MTX_SPIN);
	return (pvc);
}

void
vpvclock_cleanup(struct vpvclock *pvc)
{
	if (pvc == NULL)
		return;
	mtx_destroy(&pvc->mtx);
	free(pvc, M_VPVCLOCK);
}

/*
 * Compute the guest-visible TSC at this instant.  bhyve applies a per-vCPU TSC
 * offset to the host TSC, so guest_tsc == host_tsc + offset.  Because the
 * offset is restored to preserve continuity across pause/migrate, a value
 * derived from guest_tsc is monotonic by construction.
 */
static uint64_t
vpvclock_guest_tsc(struct vcpu *vcpu)
{
	return (rdtsc() + vm_get_tsc_offset(vcpu));
}

/*
 * Map a small guest object for writing, honouring the memseg lock so this is
 * safe both during exit emulation (vCPU frozen) and during a migration-restore
 * ioctl (vCPUs idle).  Returns a mapped, wired pointer and a release cookie, or
 * NULL if the object would span a page boundary or the GPA is not backed by
 * RAM -- a misbehaving guest cannot crash the host.
 */
static void *
vpvclock_map_guest(struct vm *vm, uint64_t gpa, size_t len, void **cookie)
{
	/*
	 * Take the memseg lock before any failure return so that every path
	 * out of this function leaves the lock held: the caller unconditionally
	 * balances a NULL result with vpvclock_unmap_guest(), which releases it.
	 * The GPA is guest-controlled, so a page-spanning object must not skip
	 * the acquire and leave the caller unlocking a lock it never held.
	 */
	vm_slock_memsegs(vm);
	if ((gpa & PAGE_MASK) + len > PAGE_SIZE)
		return (NULL);

	return (vm_gpa_hold_global(vm, gpa, len, VM_PROT_RW, cookie));
}

static void
vpvclock_unmap_guest(struct vm *vm, void *cookie)
{
	if (cookie != NULL)
		vm_gpa_release(cookie);
	vm_unlock_memsegs(vm);
}

/*
 * Record that this vCPU's time-info page needs republishing.  Runs from the
 * MSR emulation paths under vm_run()'s critical section, so it must not map
 * guest memory or take any blockable lock; the actual page write happens in
 * vpvclock_commit() once vm_run() has left the critical section.
 *
 * The unlocked system_time_enabled read is the disabled fast path: the flag
 * is only written by this vCPU's own emulation thread (or with all vCPUs
 * frozen), so it cannot change underneath us here.
 */
void
vpvclock_vcpu_update(struct vcpu *vcpu)
{
	struct vpvclock *pvc;
	struct vpvclock_vcpu *vv;

	pvc = vm_pvclock(vcpu_vm(vcpu));
	if (pvc == NULL)
		return;
	vv = &pvc->vcpus[vcpu_vcpuid(vcpu)];
	if (!vv->system_time_enabled)
		return;
	VPVCLOCK_LOCK(pvc);
	vv->publish_pending = true;
	VPVCLOCK_UNLOCK(pvc);
}

/*
 * Cheap unlocked check used by the arch run loops (with interrupts disabled,
 * inside the critical section) to decide whether to bounce back out to
 * vm_run() before re-entering the guest.  A stale false is impossible on the
 * only path that matters: the flags are set by this same thread during exit
 * emulation, before the run loop gets back to its pre-entry checks.
 */
bool
vpvclock_pending(struct vcpu *vcpu)
{
	struct vpvclock *pvc;
	struct vpvclock_vcpu *vv;

	if (vpvclock_enabled == 0)
		return (false);
	pvc = vm_pvclock(vcpu_vm(vcpu));
	if (pvc == NULL)
		return (false);
	vv = &pvc->vcpus[vcpu_vcpuid(vcpu)];
	return (vv->publish_pending || vv->wall_clock_pending);
}

/*
 * Publish this vCPU's time-info page from the recorded state.  Sleepable:
 * maps the guest page under the memseg lock.  Callers must not hold the
 * spin mutex or be inside a critical section.
 */
static void
vpvclock_publish_time_info(struct vcpu *vcpu, struct vpvclock *pvc,
    struct vpvclock_vcpu *vv)
{
	volatile struct pvclock_vcpu_time_info *ti;
	struct vm *vm;
	void *cookie;
	uint64_t gpa, guest_tsc, system_time;
	uint32_t base_version, mul, new_version;
	int8_t shift;
	uint8_t flags;

	vm = vcpu_vm(vcpu);

	VPVCLOCK_LOCK(pvc);
	if (!vv->system_time_enabled) {
		VPVCLOCK_UNLOCK(pvc);
		return;
	}
	gpa = vv->system_time_gpa;
	base_version = vv->version;
	mul = pvc->tsc_mul;
	shift = pvc->tsc_shift;
	flags = pvc->tsc_stable ? PVCLOCK_FLAG_TSC_STABLE : 0;
	VPVCLOCK_UNLOCK(pvc);

	/*
	 * A given vCPU reads only its own page, and it is not running guest
	 * code while this host thread services its exit / restore, so there is
	 * no concurrent reader of this page; the mutex only guards the shared
	 * metadata above.  Sample the guest TSC and derive the matching
	 * nanosecond base with the same scaling: the guest's read algorithm
	 * then yields the same time regardless of when the page was last
	 * refreshed, keeping it monotonic across TSC-offset changes and
	 * migration.
	 */
	guest_tsc = vpvclock_guest_tsc(vcpu);
	system_time = pvclock_scale_delta(guest_tsc, mul, shift);

	ti = vpvclock_map_guest(vm, gpa, sizeof(*ti), &cookie);
	if (ti == NULL) {
		vpvclock_unmap_guest(vm, NULL);
		return;
	}
	/* Written in place so the odd/even seqlock is visible in guest RAM. */
	new_version = vpvclock_fill_timeinfo(ti, base_version, guest_tsc,
	    system_time, mul, shift, flags);
	vpvclock_unmap_guest(vm, cookie);

	VPVCLOCK_LOCK(pvc);
	vv->version = new_version;
	VPVCLOCK_UNLOCK(pvc);
}

static void
vpvclock_write_wall_clock(struct vcpu *vcpu, uint64_t gpa)
{
	struct vm *vm = vcpu_vm(vcpu);
	struct vpvclock *pvc = vm_pvclock(vm);
	volatile struct pvclock_wall_clock *wc;
	struct timespec ts;
	void *cookie;
	uint64_t elapsed, guest_tsc;
	uint32_t version;

	/*
	 * The wall clock records real time at the moment the vCPU's system
	 * time was zero, so that guest wall time == wc + system_time.  Take the
	 * current real time and subtract the elapsed system time derived from
	 * the guest TSC with the same scaling used for the time-info page.
	 */
	getnanotime(&ts);
	guest_tsc = vpvclock_guest_tsc(vcpu);
	elapsed = pvclock_scale_delta(guest_tsc, pvc->tsc_mul, pvc->tsc_shift);
	if (ts.tv_nsec < (long)(elapsed % 1000000000ULL)) {
		ts.tv_sec -= 1;
		ts.tv_nsec += 1000000000L;
	}
	ts.tv_sec -= elapsed / 1000000000ULL;
	ts.tv_nsec -= elapsed % 1000000000ULL;

	wc = vpvclock_map_guest(vm, gpa, sizeof(*wc), &cookie);
	if (wc == NULL) {
		vpvclock_unmap_guest(vm, NULL);
		return;
	}
	/*
	 * Wall clock uses the same odd/even seqlock as the time-info page, and
	 * the guest reader only detects a torn write when the published version
	 * differs from the one it latched.  Advance a persistent counter rather
	 * than republishing the constant 2, and serialise concurrent host
	 * writers of this shared per-VM page under the lock so the version stays
	 * monotonic and the payload stores are atomic with respect to them.  The
	 * lock is taken only across the (non-sleeping) stores to the wired page,
	 * never across the memseg-locked mapping above.
	 */
	VPVCLOCK_LOCK(pvc);
	version = pvc->wall_clock_version + 1;	/* odd: update in progress */
	wc->version = version;
	__asm __volatile("" ::: "memory");
	wc->sec = (uint32_t)ts.tv_sec;
	wc->nsec = (uint32_t)ts.tv_nsec;
	__asm __volatile("" ::: "memory");
	version++;				/* even: update complete */
	wc->version = version;
	pvc->wall_clock_version = version;
	VPVCLOCK_UNLOCK(pvc);
	vpvclock_unmap_guest(vm, cookie);
}

/*
 * Consume the deferred-publish flags and perform the sleepable guest-page
 * writes.  Called from vm_run() after critical_exit() (before the next guest
 * entry) and, for the restore path, directly from ioctl context via
 * vm_restore_time() while all vCPUs are frozen.
 *
 * The unlocked pending pre-check keeps the common no-op case (one branch per
 * exit) off the spin mutex; the flags are only raised by this vCPU's own
 * thread, so a raise cannot be missed here.
 */
void
vpvclock_commit(struct vcpu *vcpu)
{
	struct vpvclock *pvc;
	struct vpvclock_vcpu *vv;
	uint64_t wall_gpa;
	bool do_time, do_wall;

	pvc = vm_pvclock(vcpu_vm(vcpu));
	if (pvc == NULL)
		return;
	vv = &pvc->vcpus[vcpu_vcpuid(vcpu)];
	if (!vv->publish_pending && !vv->wall_clock_pending)
		return;

	/*
	 * Latch and clear the pending flags atomically with reading the state
	 * they refer to, so a wrmsr that lands after this point (only possible
	 * once this vCPU is back in the guest, i.e. after the publish below
	 * has finished) raises the flags for the *next* commit rather than
	 * being lost.  If the guest disabled the page after the flag was
	 * raised, system_time_enabled is now false and the publish is
	 * correctly skipped.
	 */
	VPVCLOCK_LOCK(pvc);
	do_time = vv->publish_pending && vv->system_time_enabled;
	do_wall = vv->wall_clock_pending && pvc->wall_clock_enabled;
	wall_gpa = pvc->wall_clock_gpa;
	vv->publish_pending = false;
	vv->wall_clock_pending = false;
	VPVCLOCK_UNLOCK(pvc);

	if (do_time)
		vpvclock_publish_time_info(vcpu, pvc, vv);
	if (do_wall)
		vpvclock_write_wall_clock(vcpu, wall_gpa);
}

int
vpvclock_wrmsr(struct vcpu *vcpu, u_int msr, uint64_t val)
{
	struct vpvclock *pvc;
	struct vpvclock_vcpu *vv;

	if (!vpvclock_capable())
		return (ENOENT);
	pvc = vm_pvclock(vcpu_vm(vcpu));
	if (pvc == NULL)
		return (ENOENT);
	vv = &pvc->vcpus[vcpu_vcpuid(vcpu)];

	switch (msr) {
	case VPVCLOCK_MSR_SYSTEM_TIME:
	case VPVCLOCK_MSR_SYSTEM_TIME_NEW:
		VPVCLOCK_LOCK(pvc);
		vv->system_time_msr = val;
		if ((val & 1) != 0) {
			/* Bit 0 is the enable bit; the rest is the GPA. */
			vv->system_time_gpa = val & ~1ULL;
			vv->system_time_enabled = true;
			/* Fresh registration restarts the version sequence. */
			vv->version = 0;
			/* Publish deferred to vpvclock_commit(). */
			vv->publish_pending = true;
		} else {
			vv->system_time_enabled = false;
			/* Drop any publish the guest just revoked. */
			vv->publish_pending = false;
		}
		VPVCLOCK_UNLOCK(pvc);
		return (0);
	case VPVCLOCK_MSR_WALL_CLOCK:
	case VPVCLOCK_MSR_WALL_CLOCK_NEW:
		VPVCLOCK_LOCK(pvc);
		pvc->wall_clock_gpa = val;
		pvc->wall_clock_enabled = true;
		/*
		 * The wall clock is per-VM but the deferred publish is routed
		 * to the writing vCPU: its run loop is the one guaranteed to
		 * pass through vpvclock_commit() before the guest instruction
		 * after this WRMSR can execute.
		 */
		vv->wall_clock_pending = true;
		VPVCLOCK_UNLOCK(pvc);
		return (0);
	default:
		break;
	}
	return (ENOENT);
}

int
vpvclock_rdmsr(struct vcpu *vcpu, u_int msr, uint64_t *val)
{
	struct vpvclock *pvc;

	if (!vpvclock_capable())
		return (ENOENT);
	pvc = vm_pvclock(vcpu_vm(vcpu));
	if (pvc == NULL)
		return (ENOENT);

	switch (msr) {
	case VPVCLOCK_MSR_SYSTEM_TIME:
	case VPVCLOCK_MSR_SYSTEM_TIME_NEW:
		VPVCLOCK_LOCK(pvc);
		*val = pvc->vcpus[vcpu_vcpuid(vcpu)].system_time_msr;
		VPVCLOCK_UNLOCK(pvc);
		return (0);
	case VPVCLOCK_MSR_WALL_CLOCK:
	case VPVCLOCK_MSR_WALL_CLOCK_NEW:
		VPVCLOCK_LOCK(pvc);
		*val = pvc->wall_clock_gpa;
		VPVCLOCK_UNLOCK(pvc);
		return (0);
	default:
		break;
	}
	return (ENOENT);
}
