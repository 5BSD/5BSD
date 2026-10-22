/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Portable RISC-V bhyve checkpoint wire codec.  Like the ARM64 codec it
 * depends only on the VMS2 envelope/common-state codecs so it can be built
 * into the vmm module and into native host-side test harnesses.  Constants
 * are restated from the RISC-V privileged specification; the kernel adapter
 * asserts them against machine/riscvreg.h.
 */

#ifndef _RISCV_VMM_VMM_SNAPSHOT_RISCV_H_
#define	_RISCV_VMM_VMM_SNAPSHOT_RISCV_H_

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include <dev/vmm/vmm_snapshot_state.h>

#define	VMM_SNAPSHOT_RISCV_STATE_VERSION	1U

#define	VMM_SNAPSHOT_SECTION_RISCV_VM		UINT16_C(0x3001)
#define	VMM_SNAPSHOT_SECTION_RISCV_VCPU		UINT16_C(0x3002)
#define	VMM_SNAPSHOT_SECTION_RISCV_FP		UINT16_C(0x3003)
#define	VMM_SNAPSHOT_SECTION_RISCV_APLIC	UINT16_C(0x3010)

#define	VMM_SNAPSHOT_RISCV_MAX_VCPUS		1024U

enum vmm_snapshot_riscv_reg {
	VMM_SNAPSHOT_RISCV_RA = 0,
	VMM_SNAPSHOT_RISCV_SP,
	VMM_SNAPSHOT_RISCV_GP,
	VMM_SNAPSHOT_RISCV_TP,
	VMM_SNAPSHOT_RISCV_T0,
	VMM_SNAPSHOT_RISCV_T6 = VMM_SNAPSHOT_RISCV_T0 + 6,
	VMM_SNAPSHOT_RISCV_S0,
	VMM_SNAPSHOT_RISCV_S11 = VMM_SNAPSHOT_RISCV_S0 + 11,
	VMM_SNAPSHOT_RISCV_A0,
	VMM_SNAPSHOT_RISCV_A7 = VMM_SNAPSHOT_RISCV_A0 + 7,
	VMM_SNAPSHOT_RISCV_SEPC,	/* guest PC at the next entry */
	VMM_SNAPSHOT_RISCV_SSTATUS,	/* HS sstatus used for the guest sret */
	VMM_SNAPSHOT_RISCV_HSTATUS,
	VMM_SNAPSHOT_RISCV_HVIP,
	VMM_SNAPSHOT_RISCV_VSSTATUS,
	VMM_SNAPSHOT_RISCV_VSIE,
	VMM_SNAPSHOT_RISCV_VSTVEC,
	VMM_SNAPSHOT_RISCV_VSSCRATCH,
	VMM_SNAPSHOT_RISCV_VSEPC,
	VMM_SNAPSHOT_RISCV_VSCAUSE,
	VMM_SNAPSHOT_RISCV_VSTVAL,
	VMM_SNAPSHOT_RISCV_VSATP,
	VMM_SNAPSHOT_RISCV_SCOUNTEREN,
	VMM_SNAPSHOT_RISCV_SENVCFG,
	VMM_SNAPSHOT_RISCV_GUEST_SCOUNTEREN,
	VMM_SNAPSHOT_RISCV_TIMER_DEADLINE, /* guest time of the SBI timer */
	VMM_SNAPSHOT_RISCV_REG_COUNT
};

_Static_assert(VMM_SNAPSHOT_RISCV_REG_COUNT == 47,
    "RISC-V vCPU register wire count");

#define	VMM_SNAPSHOT_RISCV_VCPU_F_EXCEPTION	UINT32_C(0x00000001)
#define	VMM_SNAPSHOT_RISCV_VCPU_F_IPI		UINT32_C(0x00000002)
#define	VMM_SNAPSHOT_RISCV_VCPU_F_TIMER_PENDING	UINT32_C(0x00000004)
#define	VMM_SNAPSHOT_RISCV_VCPU_F_TIMER_ARMED	UINT32_C(0x00000008)
#define	VMM_SNAPSHOT_RISCV_VCPU_F_VALID		UINT32_C(0x0000000f)

#define	VMM_SNAPSHOT_RISCV_VM_F_SSTC		UINT32_C(0x00000001)
#define	VMM_SNAPSHOT_RISCV_VM_F_VALID		UINT32_C(0x00000001)

/* Architectural values restated for portable validation. */
#define	VMM_SNAPSHOT_RISCV_HSTATUS_GVA		(UINT64_C(1) << 6)
#define	VMM_SNAPSHOT_RISCV_HSTATUS_SPV		(UINT64_C(1) << 7)
#define	VMM_SNAPSHOT_RISCV_HSTATUS_SPVP		(UINT64_C(1) << 8)
#define	VMM_SNAPSHOT_RISCV_HSTATUS_VTW		(UINT64_C(1) << 21)
#define	VMM_SNAPSHOT_RISCV_HSTATUS_VSXL_SHIFT	32
#define	VMM_SNAPSHOT_RISCV_HSTATUS_VSXL_MASK	(UINT64_C(3) << 32)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_SIE		(UINT64_C(1) << 1)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_SPIE		(UINT64_C(1) << 5)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_SPP		(UINT64_C(1) << 8)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_VS_MASK	(UINT64_C(3) << 9)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_FS_MASK	(UINT64_C(3) << 13)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_XS_MASK	(UINT64_C(3) << 15)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_SUM		(UINT64_C(1) << 18)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_MXR		(UINT64_C(1) << 19)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_UXL_SHIFT	32
#define	VMM_SNAPSHOT_RISCV_SSTATUS_UXL_MASK	(UINT64_C(3) << 32)
#define	VMM_SNAPSHOT_RISCV_SSTATUS_SD		(UINT64_C(1) << 63)
#define	VMM_SNAPSHOT_RISCV_HVIP_VSSIP		(UINT64_C(1) << 2)
#define	VMM_SNAPSHOT_RISCV_HVIP_VSTIP		(UINT64_C(1) << 6)
#define	VMM_SNAPSHOT_RISCV_HVIP_VSEIP		(UINT64_C(1) << 10)
#define	VMM_SNAPSHOT_RISCV_FCSR_VALID		UINT64_C(0xff)

struct vmm_snapshot_riscv_vm {
	uint32_t	flags;
	uint32_t	timebase;	/* guest timebase-frequency */
	uint64_t	capture_time;	/* guest/host `time` at capture */
};

struct vmm_snapshot_riscv_vcpu {
	uint32_t	flags;
	uint64_t	regs[VMM_SNAPSHOT_RISCV_REG_COUNT];
};

struct vmm_snapshot_riscv_fp {
	uint64_t	f[32][2];	/* Q-capable 128-bit save slots */
	uint64_t	fcsr;
};

struct vmm_snapshot_riscv_vcpu_stage {
	uint32_t			instance;
	struct vmm_snapshot_vcpu_common	common;
	struct vmm_snapshot_riscv_vcpu	vcpu;
	struct vmm_snapshot_riscv_fp	fp;
};

struct vmm_snapshot_riscv_transaction {
	struct vmm_snapshot_vm_common	vm;
	struct vmm_snapshot_riscv_vm	riscv;
	uint32_t			vcpu_count;
};

#define	VMM_SNAPSHOT_RISCV_VM_SIZE		24U
#define	VMM_SNAPSHOT_RISCV_VCPU_HEADER_SIZE	16U
#define	VMM_SNAPSHOT_RISCV_VCPU_SIZE		(VMM_SNAPSHOT_RISCV_VCPU_HEADER_SIZE + \
	8U * VMM_SNAPSHOT_RISCV_REG_COUNT)
#define	VMM_SNAPSHOT_RISCV_FP_SIZE		(16U + 512U)

int	vmm_snapshot_riscv_vm_size(uint32_t, size_t *);
int	vmm_snapshot_riscv_vm_encode(
	    const struct vmm_snapshot_riscv_transaction *,
	    const struct vmm_snapshot_riscv_vcpu_stage *, size_t,
	    void *, size_t, size_t *);
int	vmm_snapshot_riscv_vm_decode(const void *, size_t,
	    struct vmm_snapshot_riscv_vcpu_stage *, size_t,
	    struct vmm_snapshot_riscv_transaction *);
int	vmm_snapshot_riscv_vcpu_validate(const struct vmm_snapshot_riscv_vcpu *);

/* APLIC (direct delivery mode, the only mode the VMM implements). */
#define	VMM_SNAPSHOT_RISCV_APLIC_NIRQS		63U
#define	VMM_SNAPSHOT_RISCV_APLIC_SLOTS		(VMM_SNAPSHOT_RISCV_APLIC_NIRQS + 1U)
#define	VMM_SNAPSHOT_RISCV_APLIC_DOMAINCFG_IE	UINT32_C(0x00000100)
#define	VMM_SNAPSHOT_RISCV_APLIC_SOURCECFG_D	UINT32_C(0x00000400)
#define	VMM_SNAPSHOT_RISCV_APLIC_SOURCECFG_CHILD UINT32_C(0x000003ff)
#define	VMM_SNAPSHOT_RISCV_APLIC_SOURCECFG_SM	UINT32_C(0x00000007)
#define	VMM_SNAPSHOT_RISCV_APLIC_STATE_VALID	UINT32_C(0x00000007)

struct vmm_snapshot_riscv_aplic_source {
	uint32_t	sourcecfg;
	uint32_t	state;
	uint32_t	target;
};

struct vmm_snapshot_riscv_aplic {
	struct vmm_snapshot_vm_common	vm;
	uint64_t	mem_start;
	uint64_t	mem_size;
	uint32_t	domaincfg;
	uint32_t	nirqs;
	/* Slot 0 is architecturally absent and must be zero. */
	struct vmm_snapshot_riscv_aplic_source
			sources[VMM_SNAPSHOT_RISCV_APLIC_SLOTS];
};

#define	VMM_SNAPSHOT_RISCV_APLIC_HEADER_SIZE	32U
#define	VMM_SNAPSHOT_RISCV_APLIC_SOURCE_SIZE	16U
#define	VMM_SNAPSHOT_RISCV_APLIC_PAYLOAD_SIZE	\
	(VMM_SNAPSHOT_RISCV_APLIC_HEADER_SIZE + \
	VMM_SNAPSHOT_RISCV_APLIC_SOURCE_SIZE * VMM_SNAPSHOT_RISCV_APLIC_SLOTS)

int	vmm_snapshot_riscv_aplic_size(size_t *);
int	vmm_snapshot_riscv_aplic_encode(const struct vmm_snapshot_riscv_aplic *,
	    void *, size_t, size_t *);
int	vmm_snapshot_riscv_aplic_decode(const void *, size_t,
	    struct vmm_snapshot_riscv_aplic *);
int	vmm_snapshot_riscv_aplic_validate(
	    const struct vmm_snapshot_riscv_aplic *);

#endif /* _RISCV_VMM_VMM_SNAPSHOT_RISCV_H_ */
