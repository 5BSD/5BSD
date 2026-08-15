/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _VMX_H_
#define	_VMX_H_

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include "vmcs.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_control_msr.h"
#include "vmx_nested_context.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_entry_environment_intel.h"
#include "vmx_nested_ept_binding.h"
#include "vmx_nested_ept_cache.h"
#include "vmx_nested_ept_root.h"
#include "vmx_nested_l2_portable.h"
#include "vmx_nested_l2_thaw_staged.h"
#include "vmx_nested_msr_state.h"
#include "vmx_nested_msr_workspace.h"
#include "vmx_nested_mtf_owner.h"
#include "vmx_nested_refreeze.h"
#include "vmx_nested_run.h"
#include "vmx_nested_startup_dispatch.h"
#include "vmx_nested_tsc_aux.h"
#include "vmx_nested_vmcs02_intel.h"
#include "vmx_nested_vmcs02_lease.h"
#include "vmx_nested_vmcs12.h"
#include "vmx_nested_vmcs_registry.h"
#include "vmx_nested_vmexit.h"
#include "vmx_nested_vpid_owner.h"
#include "x86.h"

struct pmap;
struct vmx;

struct vmxctx {
	register_t	guest_rdi;		/* Guest state */
	register_t	guest_rsi;
	register_t	guest_rdx;
	register_t	guest_rcx;
	register_t	guest_r8;
	register_t	guest_r9;
	register_t	guest_rax;
	register_t	guest_rbx;
	register_t	guest_rbp;
	register_t	guest_r10;
	register_t	guest_r11;
	register_t	guest_r12;
	register_t	guest_r13;
	register_t	guest_r14;
	register_t	guest_r15;
	register_t	guest_cr2;
	register_t	guest_dr0;
	register_t	guest_dr1;
	register_t	guest_dr2;
	register_t	guest_dr3;
	register_t	guest_dr6;

	register_t	host_r15;		/* Host state */
	register_t	host_r14;
	register_t	host_r13;
	register_t	host_r12;
	register_t	host_rbp;
	register_t	host_rsp;
	register_t	host_rbx;
	register_t	host_dr0;
	register_t	host_dr1;
	register_t	host_dr2;
	register_t	host_dr3;
	register_t	host_dr6;
	register_t	host_dr7;
	uint64_t	host_debugctl;
	int		host_tf;

	int		inst_fail_status;

	/*
	 * The pmap needs to be deactivated in vmx_enter_guest()
	 * so keep a copy of the 'pmap' in each vmxctx.
	 */
	struct pmap	*pmap;
};

struct vmxcap {
	int	set;
	uint32_t proc_ctls;
	uint32_t proc_ctls2;
	uint32_t exc_bitmap;
};

struct vmxstate {
	uint64_t nextrip;	/* next instruction to be executed by guest */
	int	lastcpu;	/* host cpu that this 'vcpu' last ran on */
	uint16_t vpid;
};

struct apic_page {
	uint32_t reg[PAGE_SIZE / 4];
};
CTASSERT(sizeof(struct apic_page) == PAGE_SIZE);

/* Posted Interrupt Descriptor (described in section 29.6 of the Intel SDM) */
struct pir_desc {
	uint64_t	pir[4];
	uint64_t	pending;
	uint64_t	unused[3];
} __aligned(64);
CTASSERT(sizeof(struct pir_desc) == 64);

/* Index into the 'guest_msrs[]' array */
enum {
	IDX_MSR_LSTAR,
	IDX_MSR_CSTAR,
	IDX_MSR_STAR,
	IDX_MSR_SF_MASK,
	IDX_MSR_KGSBASE,
	IDX_MSR_PAT,
	IDX_MSR_TSC_AUX,
	GUEST_MSR_NUM		/* must be the last enumeration */
};

enum vmx_nested_hardware_msr_transition {
	VMX_NESTED_HARDWARE_MSR_NONE = 0,
	VMX_NESTED_HARDWARE_MSR_ENTRY,
	VMX_NESTED_HARDWARE_MSR_EXIT,
};

struct vmx_vcpu {
	struct vmx	*vmx;
	struct vcpu	*vcpu;
	struct vmcs	*vmcs;
	struct vmcs	*nested_vmcs02;
	struct apic_page *apic_page;
	struct pir_desc	*pir_desc;
	uint64_t	guest_msrs[GUEST_MSR_NUM];
	struct vmxctx	ctx;
	struct vmxcap	cap;
	struct vmxstate	state;
	/*
	 * Runtime-only nested state owner.  It is initialized even while
	 * nested VMX exposure is disabled so reset, snapshot, and teardown do
	 * not acquire an implicit dependency on guest exposure.
	 */
	struct vmx_nested_context nested;
	/*
	 * Virtual IA32_FEATURE_CONTROL value.  This remains zero after vCPU
	 * creation until the guest writes it through the nested-VMX MSR
	 * interface.  It is never initialized from the host MSR.
	 */
	struct vmx_nested_control_msr_state nested_control_msrs;
	struct vmx_nested_entry_runtime nested_entry_runtime;
	struct vmx_nested_l0_continuation nested_l0_continuation;
	/*
	 * Runtime-only monitor-trap obligation.  A pending owner is bound to one
	 * VMCS12 execution identity and the portable generation which created it.
	 * It is never serialized: freeze must first move it into a strictly newer
	 * portable L2 image, and thaw may publish it only after L2 really enters.
	 */
	struct vmx_nested_mtf_owner nested_mtf_owner;
	struct vmx_nested_startup_dispatch nested_startup_dispatch;
	struct vmx_nested_l2_portable_state nested_l2_portable;
	struct vmx_nested_l2_thaw_staged nested_l2_thaw_staged;
	struct vmx_nested_refreeze_staged nested_refreeze_staged;
	/*
	 * Destination-local cold-thaw resources.  They are acquired by the
	 * frozen stage and published to the active entry fields only after
	 * the CPU-pinned stage has installed L2 state successfully.
	 */
	struct vmx_nested_entry_environment nested_thaw_environment;
	struct vmx_nested_vmcs02_resources nested_thaw_fixed_resources;
	struct vmx_nested_vmcs02_resources nested_thaw_resources;
	bool		nested_thaw_resources_valid;
	uint64_t	nested_portable_generation;
	uint64_t	nested_exit_sequence;
	bool		nested_l2_portable_valid;
	/*
	 * A later hot VMRESUME failure is fatal to this VM run, but its
	 * CPU-local state is detached synchronously.  Opaque leases are
	 * released later by the frozen teardown owner because that operation
	 * may sleep.  Keep the domain crossing explicit and fail-stop.
	 */
	bool		nested_hot_failure_detached;
	/*
	 * Frozen VMCS12 values for the entry_runtime transaction.  This is
	 * valid only while that runtime is non-idle and is never serialized.
	 */
	struct vmx_nested_vmcs12_snapshot nested_vmcs12_snapshot;
	/*
	 * Coherent VMCS01/L1 environment paired with the frozen VMCS12
	 * snapshot above.  It is value-only runtime state and is published
	 * only after the architecture adapter completes an atomic capture.
	 */
	struct vmx_nested_entry_environment nested_entry_environment;
	/*
	 * Frozen prospective L2 transaction.  The plan and software-only
	 * MSRs contain values, never host pointers.  They are retained only
	 * while entry_runtime owns the matching execution identifier.
	 */
	struct vmx_nested_vmcs02_plan nested_vmcs02_plan;
	struct vmx_nested_software_msrs nested_l1_software_msrs;
	struct vmx_nested_software_msrs nested_l2_software_msrs;
	struct vmx_nested_vmcs02_resources nested_vmcs02_resources;
	uint64_t	nested_msr_generation;
	uint32_t	nested_entry_msr_count;
	bool		nested_vmcs02_plan_valid;
	/*
	 * Hardware rollback image for the software-owned MSR bank.  Entry
	 * owns it until successful VM entry.  A destructive VMCS02 exit
	 * switches back to L1 and commits that hardware transition while
	 * still CPU-pinned, before the ordinary vmx_run() host-MSR restore.
	 * Frozen VMCS12/L1 publication therefore never owns or touches
	 * CPU-local MSRs.
	 */
	struct vmx_nested_msr_entry nested_hardware_msr_rollback[
	    VMX_NESTED_SOFTWARE_MSR_COUNT];
	struct vmx_nested_software_msrs
	    nested_hardware_msr_rollback_software;
	uint32_t	nested_hardware_msr_count;
	enum vmx_nested_hardware_msr_transition
			nested_hardware_msr_transition;
	enum vmx_nested_tsc_aux_residency
			nested_tsc_aux_residency;
	enum vmx_nested_tsc_aux_residency
			nested_tsc_aux_rollback_residency;
	struct vmx_nested_ept_root_backend nested_ept_backend;
	struct vmx_nested_ept_cache nested_ept_cache;
	struct vmx_nested_ept_cache_entry nested_ept_entries[8];
	struct vmx_nested_ept_binding nested_ept_binding;
	struct vmx_nested_vmcs02_intel nested_vmcs02_intel;
	struct vmx_nested_vmcs02_lease_owner nested_vmcs02_leases;
	struct vmx_nested_vpid_owner nested_vpid_owner;
	struct vmx_nested_msr_workspace nested_msr_workspace;
	struct vmx_nested_msr_entry *nested_msr_storage;
	/*
	 * Frozen, retry-safe VM-exit MSR transaction.  Once guest-memory
	 * stores commit, retries resume from the recorded phase and reuse the
	 * same value-only L1 load image instead of repeating stores or
	 * resampling a completed load list.
	 */
	struct vmx_nested_exit_msr_transaction nested_exit_msr_transaction;
	struct vmx_nested_vmexit_state_plan nested_exit_msr_plan;
	struct vmx_nested_failed_entry_state_plan
			nested_failed_entry_msr_plan;
	struct vmx_nested_software_msrs nested_exit_msr_software;
	bool		nested_exit_msr_plan_valid;
	bool		nested_failed_entry_msr_plan_valid;
	/*
	 * Complete VMCS12 staging image for ordinary nested exits.  Allocate
	 * it before the vCPU can run: the exit path must remain allocation
	 * free while committing L2 state transactionally.
	 */
	char		*nested_vmcs_scratch;
	/*
	 * Per-vCPU because each L1 VMCS can request a different MSR
	 * interception policy.  Hardware VMCS02 never references VMCS12's
	 * guest-physical bitmap directly.  The second page is transactional
	 * scratch: a failed L1 read must not alter the active hardware page.
	 */
	uint8_t		*nested_msr_bitmap;
	uint8_t		*nested_l1_msr_bitmap;
	uint8_t		*nested_msr_bitmap_scratch;
	uint8_t		*nested_l1_io_bitmap;
	uint8_t		*nested_l1_io_bitmap_scratch;
	struct vm_mtrr  mtrr;
	int		vcpuid;
};

struct vmx_nested_snapshot_vcpu_stage {
	struct vmx_vcpu *vcpu;
	struct vmx_nested_context context;
	struct vmx_nested_control_msr_state control;
	struct vmx_nested_l0_continuation continuation;
	struct vmx_nested_entry_runtime runtime;
	struct vmx_nested_l2_portable_state portable;
	struct vmx_nested_vmcs12_snapshot snapshot;
	struct vmx_nested_entry_environment environment;
	struct vmx_nested_vmcs02_plan plan;
	struct vmx_nested_software_msrs l1_software;
	struct vmx_nested_vpid_owner vpid_owner;
	/*
	 * Fresh destination MSR scratch belongs to the unpublished restore
	 * stage until the VM-wide registry transaction succeeds.  It is not
	 * checkpoint data and must not become a destination vCPU allocation on
	 * a later decode or commit failure.
	 */
	struct vmx_nested_msr_workspace msr_workspace;
	struct vmx_nested_msr_entry *msr_storage;
	uint64_t msr_generation;
	bool msr_workspace_staged;
	bool vpid_staged;
	bool active_l2;
	bool valid;
};

struct vmx_snapshot_arch_vcpu_stage;

struct vmx_nested_snapshot_restore {
	struct vmx_nested_vmcs_registry registry;
	struct vmx_nested_snapshot_vcpu_stage *vcpus;
	struct vmx_snapshot_arch_vcpu_stage *arch_vcpus;
	uint16_t maxcpus;
	bool registry_initialized;
};

/* virtual machine softc */
struct vmx {
	struct vm	*vm;
	struct sx	nested_vmcs_sx;
	struct vmx_nested_vmcs_registry nested_vmcs_registry;
	struct vmx_nested_snapshot_restore *nested_snapshot_restore;
	/*
	 * VMX is part of the guest CPU model, not a per-vCPU scheduling
	 * control.  Bit 0 is the configured value and bit 1 makes that value
	 * immutable after any vCPU has entered the run path.
	 */
	u_int		nested_vmx_exposure;
	char		*msr_bitmap;
	uint64_t	eptp;
	long		eptgen[MAXCPU];		/* cached pmap->pm_eptgen */
	pmap_t		pmap;
};

extern bool vmx_have_msr_tsc_aux;

#define	VMX_CTR0(vcpu, format)						\
	VCPU_CTR0((vcpu)->vmx->vm, (vcpu)->vcpuid, format)

#define	VMX_CTR1(vcpu, format, p1)					\
	VCPU_CTR1((vcpu)->vmx->vm, (vcpu)->vcpuid, format, p1)

#define	VMX_CTR2(vcpu, format, p1, p2)					\
	VCPU_CTR2((vcpu)->vmx->vm, (vcpu)->vcpuid, format, p1, p2)

#define	VMX_CTR3(vcpu, format, p1, p2, p3)				\
	VCPU_CTR3((vcpu)->vmx->vm, (vcpu)->vcpuid, format, p1, p2, p3)

#define	VMX_CTR4(vcpu, format, p1, p2, p3, p4)				\
	VCPU_CTR4((vcpu)->vmx->vm, (vcpu)->vcpuid, format, p1, p2, p3, p4)

#define	VMX_GUEST_VMEXIT	0
#define	VMX_VMRESUME_ERROR	1
#define	VMX_VMLAUNCH_ERROR	2
int	vmx_enter_guest(struct vmxctx *ctx, struct vmx *vmx, int launched);
void	vmx_call_isr(uintptr_t entry);

u_long	vmx_fix_cr0(u_long cr0);
u_long	vmx_fix_cr4(u_long cr4);

int	vmx_set_tsc_offset(struct vmx_vcpu *vcpu, uint64_t offset);
int	vmx_nested_write_tsc(struct vmx_vcpu *vcpu, uint64_t value);

extern char	vmx_exit_guest[];
extern char	vmx_exit_guest_flush_rsb[];

#endif
