/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Portable ARM64 bhyve checkpoint wire codec.
 *
 * This file and vmm_snapshot_arm64.c deliberately depend only on the VMS2
 * envelope/common-state codecs and <sys/endian.h>, so the same objects are
 * compiled into the arm64 vmm kernel module and into native userland test
 * harnesses on any host.  Architectural constants used for validation are
 * restated here; the kernel adapter asserts that they match the machine
 * headers.
 */

#ifndef _ARM64_VMM_VMM_SNAPSHOT_ARM64_H_
#define	_ARM64_VMM_VMM_SNAPSHOT_ARM64_H_

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include <dev/vmm/vmm_snapshot_state.h>

#define	VMM_SNAPSHOT_ARM64_STATE_VERSION	1U

#define	VMM_SNAPSHOT_SECTION_ARM64_VM		UINT16_C(0x2001)
#define	VMM_SNAPSHOT_SECTION_ARM64_VCPU		UINT16_C(0x2002)
#define	VMM_SNAPSHOT_SECTION_ARM64_FP		UINT16_C(0x2003)
#define	VMM_SNAPSHOT_SECTION_ARM64_TIMER	UINT16_C(0x2004)
#define	VMM_SNAPSHOT_SECTION_ARM64_VGIC_DIST	UINT16_C(0x2010)
#define	VMM_SNAPSHOT_SECTION_ARM64_VGIC_CPU	UINT16_C(0x2011)

/* Upper bound used to size kernel staging; the ABI supports fewer CPUs. */
#define	VMM_SNAPSHOT_ARM64_MAX_VCPUS		1024U

enum vmm_snapshot_arm64_reg {
	VMM_SNAPSHOT_ARM64_X0 = 0,
	VMM_SNAPSHOT_ARM64_X30 = VMM_SNAPSHOT_ARM64_X0 + 30,
	VMM_SNAPSHOT_ARM64_SP_EL0,
	VMM_SNAPSHOT_ARM64_PC,		/* ELR_EL2 at the next guest entry */
	VMM_SNAPSHOT_ARM64_PSTATE,	/* SPSR_EL2 at the next guest entry */
	VMM_SNAPSHOT_ARM64_SP_EL1,
	VMM_SNAPSHOT_ARM64_ELR_EL1,
	VMM_SNAPSHOT_ARM64_SPSR_EL1,
	VMM_SNAPSHOT_ARM64_SCTLR_EL1,
	VMM_SNAPSHOT_ARM64_TTBR0_EL1,
	VMM_SNAPSHOT_ARM64_TTBR1_EL1,
	VMM_SNAPSHOT_ARM64_TCR_EL1,
	VMM_SNAPSHOT_ARM64_MAIR_EL1,
	VMM_SNAPSHOT_ARM64_AMAIR_EL1,
	VMM_SNAPSHOT_ARM64_ESR_EL1,
	VMM_SNAPSHOT_ARM64_FAR_EL1,
	VMM_SNAPSHOT_ARM64_AFSR0_EL1,
	VMM_SNAPSHOT_ARM64_AFSR1_EL1,
	VMM_SNAPSHOT_ARM64_VBAR_EL1,
	VMM_SNAPSHOT_ARM64_CONTEXTIDR_EL1,
	VMM_SNAPSHOT_ARM64_CPACR_EL1,
	VMM_SNAPSHOT_ARM64_ACTLR_EL1,
	VMM_SNAPSHOT_ARM64_PAR_EL1,
	VMM_SNAPSHOT_ARM64_CSSELR_EL1,
	VMM_SNAPSHOT_ARM64_MDSCR_EL1,
	VMM_SNAPSHOT_ARM64_MDCCINT_EL1,
	VMM_SNAPSHOT_ARM64_TPIDR_EL0,
	VMM_SNAPSHOT_ARM64_TPIDRRO_EL0,
	VMM_SNAPSHOT_ARM64_TPIDR_EL1,
	VMM_SNAPSHOT_ARM64_DBGCLAIMSET_EL1,
	/* Host-assigned identity; checked, never applied, on restore. */
	VMM_SNAPSHOT_ARM64_VMPIDR_EL2,
	VMM_SNAPSHOT_ARM64_VPIDR_EL2,
	VMM_SNAPSHOT_ARM64_PMCR_EL0,
	VMM_SNAPSHOT_ARM64_PMCCNTR_EL0,
	VMM_SNAPSHOT_ARM64_PMCCFILTR_EL0,
	VMM_SNAPSHOT_ARM64_PMUSERENR_EL0,
	VMM_SNAPSHOT_ARM64_PMSELR_EL0,
	VMM_SNAPSHOT_ARM64_PMXEVCNTR_EL0,
	VMM_SNAPSHOT_ARM64_PMCNTENSET_EL0,
	VMM_SNAPSHOT_ARM64_PMINTENSET_EL1,
	VMM_SNAPSHOT_ARM64_PMOVSSET_EL0,
	VMM_SNAPSHOT_ARM64_PMEVCNTR0_EL0,
	VMM_SNAPSHOT_ARM64_PMEVCNTR30_EL0 = VMM_SNAPSHOT_ARM64_PMEVCNTR0_EL0 + 30,
	VMM_SNAPSHOT_ARM64_PMEVTYPER0_EL0,
	VMM_SNAPSHOT_ARM64_PMEVTYPER30_EL0 =
	    VMM_SNAPSHOT_ARM64_PMEVTYPER0_EL0 + 30,
	VMM_SNAPSHOT_ARM64_DBGBCR0_EL1,
	VMM_SNAPSHOT_ARM64_DBGBCR15_EL1 = VMM_SNAPSHOT_ARM64_DBGBCR0_EL1 + 15,
	VMM_SNAPSHOT_ARM64_DBGBVR0_EL1,
	VMM_SNAPSHOT_ARM64_DBGBVR15_EL1 = VMM_SNAPSHOT_ARM64_DBGBVR0_EL1 + 15,
	VMM_SNAPSHOT_ARM64_DBGWCR0_EL1,
	VMM_SNAPSHOT_ARM64_DBGWCR15_EL1 = VMM_SNAPSHOT_ARM64_DBGWCR0_EL1 + 15,
	VMM_SNAPSHOT_ARM64_DBGWVR0_EL1,
	VMM_SNAPSHOT_ARM64_DBGWVR15_EL1 = VMM_SNAPSHOT_ARM64_DBGWVR0_EL1 + 15,
	VMM_SNAPSHOT_ARM64_REG_COUNT
};

_Static_assert(VMM_SNAPSHOT_ARM64_REG_COUNT == 196,
    "ARM64 vCPU register wire count");

/* vCPU flags. */
#define	VMM_SNAPSHOT_ARM64_VCPU_F_EXCEPTION	UINT32_C(0x00000001)
#define	VMM_SNAPSHOT_ARM64_VCPU_F_OSLOCK	UINT32_C(0x00000002)
#define	VMM_SNAPSHOT_ARM64_VCPU_F_VALID		UINT32_C(0x00000003)

/* Architectural values restated for portable validation. */
#define	VMM_SNAPSHOT_ARM64_PSR_M_MASK		UINT64_C(0x000000000000000f)
#define	VMM_SNAPSHOT_ARM64_PSR_M_32		UINT64_C(0x0000000000000010)
#define	VMM_SNAPSHOT_ARM64_PSR_M_EL0t		UINT64_C(0x0000000000000000)
#define	VMM_SNAPSHOT_ARM64_PSR_M_EL1t		UINT64_C(0x0000000000000004)
#define	VMM_SNAPSHOT_ARM64_PSR_M_EL1h		UINT64_C(0x0000000000000005)
#define	VMM_SNAPSHOT_ARM64_PMCR_N_SHIFT		11
#define	VMM_SNAPSHOT_ARM64_PMCR_N_MASK		UINT64_C(0x000000000000f800)
#define	VMM_SNAPSHOT_ARM64_FPSR_VALID		UINT32_C(0xf800009f)
#define	VMM_SNAPSHOT_ARM64_CNT_CTL_VALID	UINT64_C(0x0000000000000007)
#define	VMM_SNAPSHOT_ARM64_GICD_CTLR_G1A	UINT32_C(0x00000002)
#define	VMM_SNAPSHOT_ARM64_GICD_CTLR_ARE_NS	UINT32_C(0x00000010)
/*
 * The kernel's GICD_AFF (gic_v3_reg.h) is AFF0|AFF1|AFF1|AFF3, i.e. it omits
 * AFF2.  Routing state is masked with that value, so the wire contract uses
 * the same mask; the kernel adapter asserts the equality.
 */
#define	VMM_SNAPSHOT_ARM64_GICD_AFF		UINT64_C(0x000000ff0000ffff)
#define	VMM_SNAPSHOT_ARM64_ICH_HCR_EN		UINT64_C(0x0000000000000001)
#define	VMM_SNAPSHOT_ARM64_ICH_VMCR_VALID	UINT64_C(0x00000000fffc021f)

struct vmm_snapshot_arm64_vm {
	uint64_t	cntfrq;		/* CNTFRQ_EL0 seen by the guest */
	uint64_t	guest_count;	/* guest virtual counter at capture */
};

struct vmm_snapshot_arm64_vcpu {
	uint32_t	flags;
	uint64_t	regs[VMM_SNAPSHOT_ARM64_REG_COUNT];
};

struct vmm_snapshot_arm64_fp {
	uint8_t		vregs[32][16];	/* little-endian 128-bit V0-V31 */
	uint32_t	fpcr;
	uint32_t	fpsr;
};

struct vmm_snapshot_arm64_timer {
	uint32_t	cntkctl;
	uint64_t	virt_ctl;
	uint64_t	virt_cval;
	uint64_t	phys_ctl;
	uint64_t	phys_cval;
};

struct vmm_snapshot_arm64_vcpu_stage {
	uint32_t			instance;
	struct vmm_snapshot_vcpu_common	common;
	struct vmm_snapshot_arm64_vcpu	vcpu;
	struct vmm_snapshot_arm64_fp	fp;
	struct vmm_snapshot_arm64_timer	timer;
};

struct vmm_snapshot_arm64_transaction {
	struct vmm_snapshot_vm_common	vm;
	struct vmm_snapshot_arm64_vm	arm64;
	uint32_t			vcpu_count;
};

#define	VMM_SNAPSHOT_ARM64_VM_SIZE		24U
#define	VMM_SNAPSHOT_ARM64_VCPU_HEADER_SIZE	16U
#define	VMM_SNAPSHOT_ARM64_VCPU_SIZE		(VMM_SNAPSHOT_ARM64_VCPU_HEADER_SIZE + \
	8U * VMM_SNAPSHOT_ARM64_REG_COUNT)
#define	VMM_SNAPSHOT_ARM64_FP_SIZE		(16U + 512U)
#define	VMM_SNAPSHOT_ARM64_TIMER_SIZE		40U

int	vmm_snapshot_arm64_vm_size(uint32_t, size_t *);
int	vmm_snapshot_arm64_vm_encode(
	    const struct vmm_snapshot_arm64_transaction *,
	    const struct vmm_snapshot_arm64_vcpu_stage *, size_t,
	    void *, size_t, size_t *);
int	vmm_snapshot_arm64_vm_decode(const void *, size_t,
	    struct vmm_snapshot_arm64_vcpu_stage *, size_t,
	    struct vmm_snapshot_arm64_transaction *);
int	vmm_snapshot_arm64_vcpu_validate(const struct vmm_snapshot_arm64_vcpu *);

/*
 * GICv3 distributor/redistributor state.  bhyve's vGIC exposes interrupt
 * IDs 0..1022 (VGIC_NIRQS): 16 SGIs and 16 PPIs per CPU plus 991 shared SPIs.
 * LPIs are not implemented by the VMM and have no wire representation.
 */
#define	VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT	32U
#define	VMM_SNAPSHOT_ARM64_VGIC_SGI_COUNT	16U
#define	VMM_SNAPSHOT_ARM64_VGIC_NIRQS		1023U
#define	VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT	(VMM_SNAPSHOT_ARM64_VGIC_NIRQS - \
	VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT)
#define	VMM_SNAPSHOT_ARM64_VGIC_LR_MAX		16U
#define	VMM_SNAPSHOT_ARM64_VGIC_APR_MAX		4U

#define	VMM_SNAPSHOT_ARM64_IRQ_F_ACTIVE		0x01U
#define	VMM_SNAPSHOT_ARM64_IRQ_F_PENDING	0x02U
#define	VMM_SNAPSHOT_ARM64_IRQ_F_ENABLED	0x04U
#define	VMM_SNAPSHOT_ARM64_IRQ_F_LEVEL		0x08U
#define	VMM_SNAPSHOT_ARM64_IRQ_F_APLIST		0x10U
#define	VMM_SNAPSHOT_ARM64_IRQ_F_VALID		0x1fU

#define	VMM_SNAPSHOT_ARM64_IRQ_CONFIG_LEVEL	0x0U
#define	VMM_SNAPSHOT_ARM64_IRQ_CONFIG_EDGE	0x2U

struct vmm_snapshot_arm64_vgic_irq {
	uint64_t	mpidr;
	int32_t		target_vcpu;	/* -1: route matches no vCPU */
	uint8_t		flags;
	uint8_t		priority;
	uint8_t		config;
};

struct vmm_snapshot_arm64_vgic_dist {
	uint64_t	dist_start;
	uint64_t	dist_size;
	uint64_t	redist_start;
	uint64_t	redist_size;
	uint32_t	gicd_ctlr;
	uint32_t	min_prio;	/* VPMR value for the lowest priority */
	uint16_t	lr_num;
	uint16_t	apr_num;
	struct vmm_snapshot_arm64_vgic_irq
			spis[VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT];
};

struct vmm_snapshot_arm64_vgic_cpu {
	uint64_t	ich_hcr;
	uint64_t	ich_vmcr;
	uint32_t	ap0r[VMM_SNAPSHOT_ARM64_VGIC_APR_MAX];
	uint32_t	ap1r[VMM_SNAPSHOT_ARM64_VGIC_APR_MAX];
	struct vmm_snapshot_arm64_vgic_irq
			private_irqs[VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT];
	/* Exact active/pending list order: interrupt IDs, head first. */
	uint32_t	aplist_count;
	uint16_t	aplist[VMM_SNAPSHOT_ARM64_VGIC_NIRQS];
};

struct vmm_snapshot_arm64_vgic_stage {
	uint32_t			instance;
	struct vmm_snapshot_arm64_vgic_cpu cpu;
};

struct vmm_snapshot_arm64_vgic_transaction {
	struct vmm_snapshot_vm_common	vm;
	struct vmm_snapshot_arm64_vgic_dist dist;
	uint32_t			vcpu_count;
};

#define	VMM_SNAPSHOT_ARM64_VGIC_IRQ_SIZE	16U
#define	VMM_SNAPSHOT_ARM64_VGIC_DIST_HEADER_SIZE 56U
#define	VMM_SNAPSHOT_ARM64_VGIC_DIST_SIZE	\
	(VMM_SNAPSHOT_ARM64_VGIC_DIST_HEADER_SIZE + \
	VMM_SNAPSHOT_ARM64_VGIC_IRQ_SIZE * VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT)
#define	VMM_SNAPSHOT_ARM64_VGIC_CPU_HEADER_SIZE	56U
#define	VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE	\
	(VMM_SNAPSHOT_ARM64_VGIC_CPU_HEADER_SIZE + \
	VMM_SNAPSHOT_ARM64_VGIC_IRQ_SIZE * VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT)
#define	VMM_SNAPSHOT_ARM64_VGIC_CPU_MAX_SIZE	\
	(VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE + \
	((2U * VMM_SNAPSHOT_ARM64_VGIC_NIRQS + 7U) & ~7U))

int	vmm_snapshot_arm64_vgic_size(uint32_t, size_t *);
int	vmm_snapshot_arm64_vgic_encode(
	    const struct vmm_snapshot_arm64_vgic_transaction *,
	    const struct vmm_snapshot_arm64_vgic_stage *, size_t,
	    void *, size_t, size_t *);
int	vmm_snapshot_arm64_vgic_decode(const void *, size_t,
	    struct vmm_snapshot_arm64_vgic_stage *, size_t,
	    struct vmm_snapshot_arm64_vgic_transaction *);
int	vmm_snapshot_arm64_vgic_validate(
	    const struct vmm_snapshot_arm64_vgic_transaction *,
	    const struct vmm_snapshot_arm64_vgic_stage *, size_t);

#endif /* _ARM64_VMM_VMM_SNAPSHOT_ARM64_H_ */
