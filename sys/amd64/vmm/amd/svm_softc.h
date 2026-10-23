/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013 Anish Gupta (akgupt3@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SVM_SOFTC_H_
#define _SVM_SOFTC_H_

#include "x86.h"
#include "nested_svm_msr.h"
#include <dev/vmm/vmm_startup_event.h>

#define SVM_IO_BITMAP_SIZE	(3 * PAGE_SIZE)
#define SVM_MSR_BITMAP_SIZE	(2 * PAGE_SIZE)

struct svm_softc;
struct svm_nested_npt_root;

#define SVM_NESTED_VNMI_SLOTS 16
#define SVM_NESTED_VNMI_VALID (1ULL << 63)
#define SVM_NESTED_VNMI_BLOCKED (1ULL << 62)

struct dbg {
	uint32_t	rflags_tf;   /* saved RFLAGS.TF value when single-stepping a vcpu */
	bool		popf_sstep;  /* indicates that we've stepped over popf */
	bool		pushf_sstep; /* indicates that we've stepped over pushf */
};

struct asid {
	uint64_t	gen;	/* range is [1, ~0UL] */
	uint32_t	num;	/* range is [1, nasid - 1] */
};

enum svm_nested_instruction_kind {
	SVM_NESTED_INSTRUCTION_NONE,
	SVM_NESTED_INSTRUCTION_VMRUN,
	SVM_NESTED_INSTRUCTION_VMLOAD,
	SVM_NESTED_INSTRUCTION_VMSAVE,
	SVM_NESTED_L2_EXIT,
	SVM_NESTED_L2_PENDING_EVENT,
	SVM_NESTED_INIT_GIF_RECHECK,
};

struct svm_nested_instruction_pending {
	enum svm_nested_instruction_kind kind;
	uint64_t vmcb_gpa;
	uint64_t rip;
	uint64_t next_rip;
};

enum svm_startup_claim_phase {
	SVM_STARTUP_CLAIM_EMPTY = 0,
	SVM_STARTUP_CLAIM_HELD,
	/* An intercepted INIT still waits for L1 to enable GIF. */
	SVM_STARTUP_CLAIM_INIT_REFLECTED,
	SVM_STARTUP_CLAIM_FINISH_PENDING,
	SVM_STARTUP_CLAIM_POISONED,
};

struct svm_vcpu {
	struct svm_softc *sc;
	struct vcpu	*vcpu;
	struct vmcb	*vmcb;	 /* hardware saved vcpu context */
	/* Frozen-restore candidate; never used for VMRUN residency. */
	struct vmcb	*snapshot_vmcb;
	struct vmcb	*nested_vmcb12;
	struct vmcb	*nested_vmcb02; /* L0-owned L2 hardware VMCB */
	struct svm_nested_npt_root *nested_npt02;
	struct svm_regctx swctx; /* software saved vcpu context */
	uint64_t	vmcb_pa; /* VMCB physical address */
	uint64_t	nextrip; /* next instruction to be executed by guest */
        int		lastcpu; /* host cpu that the vcpu last ran on */
	uint32_t	dirty;	 /* state cache bits that must be cleared */
	long		eptgen;	 /* pmap->pm_eptgen when the vcpu last ran */
	struct asid	asid;
	long		nested_eptgen; /* NPT02 generation, separate from L1 */
	struct asid	nested_asid; /* distinct hardware ASID for L2 */
	struct vm_mtrr  mtrr;
	struct svm_nested_msr_state nested_msr;
	/* Guest SVM CPUID policy is immutable after first run or checkpoint. */
	bool		nested_config_locked;
	/* Transient, storage-bound ownership of a kernel INIT/SIPI event. */
	struct vmm_startup_event_claim startup_claim;
	enum svm_startup_claim_phase startup_claim_phase;
	struct svm_nested_instruction_pending nested_pending;
	uint64_t	nested_vmcb12_gpa;
	uint64_t	nested_npt12_root_gpa;
	uint64_t	nested_l1_next_rip;
	/* L2 VMCB GPAs with pending or blocked virtual NMIs. */
	uint64_t	nested_vnmi_gpas[SVM_NESTED_VNMI_SLOTS];
	bool		nested_active;
	bool		nested_gif;
	bool		nested_poisoned;
	/* RFLAGS.TF capability was armed while running L2. */
	bool		nested_debug_step_l2;
	int		vcpuid;
	struct dbg	dbg;
	int		caps;	 /* optional vm capabilities */
};

#ifdef BHYVE_SNAPSHOT
/*
 * Restore records are decoded one vCPU at a time because the established wire
 * format is sequential.  Keep their results unpublished until the common
 * VMM snapshot dispatcher reaches its one VM-wide completion boundary.
 */
struct svm_snapshot_vcpu_stage {
	struct svm_vcpu	*vcpu;
	struct svm_regctx swctx;
	uint64_t	nextrip;
	struct vm_mtrr	mtrr;
	struct svm_nested_msr_state nested_msr;
	struct vmcb	*nested_vmcb12;
	struct vmcb	*nested_vmcb02;
	struct svm_nested_npt_root *nested_npt02;
	uint64_t	nested_vmcb12_gpa;
	uint64_t	nested_npt12_root_gpa;
	uint64_t	nested_l1_next_rip;
	uint64_t	nested_vnmi_gpas[SVM_NESTED_VNMI_SLOTS];
	bool		nested_active;
	bool		nested_gif;
	bool		valid;
};

struct svm_snapshot_restore {
	struct svm_snapshot_vcpu_stage *vcpus;
	uint16_t	maxcpus;
	uint32_t	version;
	bool		legacy;
};
#endif

/*
 * SVM softc, one per virtual machine.
 */
struct svm_softc {
	vm_paddr_t 	nptp;			    /* nested page table */
	uint8_t		*iopm_bitmap;    /* shared by all vcpus */
	uint8_t		*msr_bitmap;    /* shared by all vcpus */
	uint8_t		*nested_msr_bitmap; /* all L2 MSRs intercept */
	struct vm	*vm;
#ifdef BHYVE_SNAPSHOT
	struct svm_snapshot_restore *snapshot_restore;
#endif
};

#define	SVM_CTR0(vcpu, format)						\
	VCPU_CTR0((vcpu)->sc->vm, (vcpu)->vcpuid, format)

#define	SVM_CTR1(vcpu, format, p1)					\
	VCPU_CTR1((vcpu)->sc->vm, (vcpu)->vcpuid, format, p1)

#define	SVM_CTR2(vcpu, format, p1, p2)					\
	VCPU_CTR2((vcpu)->sc->vm, (vcpu)->vcpuid, format, p1, p2)

#define	SVM_CTR3(vcpu, format, p1, p2, p3)				\
	VCPU_CTR3((vcpu)->sc->vm, (vcpu)->vcpuid, format, p1, p2, p3)

#define	SVM_CTR4(vcpu, format, p1, p2, p3, p4)				\
	VCPU_CTR4((vcpu)->sc->vm, (vcpu)->vcpuid, format, p1, p2, p3, p4)

static __inline struct vmcb *
svm_get_vmcb(struct svm_vcpu *vcpu)
{

	return (vcpu->vmcb);
}

static __inline struct vmcb_state *
svm_get_vmcb_state(struct svm_vcpu *vcpu)
{

	return (&vcpu->vmcb->state);
}

static __inline struct vmcb_ctrl *
svm_get_vmcb_ctrl(struct svm_vcpu *vcpu)
{

	return (&vcpu->vmcb->ctrl);
}

static __inline struct svm_regctx *
svm_get_guest_regctx(struct svm_vcpu *vcpu)
{

	return (&vcpu->swctx);
}

static __inline void
svm_set_dirty(struct svm_vcpu *vcpu, uint32_t dirtybits)
{

        vcpu->dirty |= dirtybits;
}

#endif /* _SVM_SOFTC_H_ */
