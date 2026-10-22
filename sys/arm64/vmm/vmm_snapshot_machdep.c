/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * ARM64 kernel side of bhyve checkpoint/restore (BHYVE_SNAPSHOT only).
 *
 * VM_SNAPSHOT_REQ records:
 *   STRUCT_VM   vCPU registers, EL1 system/PMU/debug registers, FP/SIMD,
 *               generic timers and the guest virtual counter.
 *   STRUCT_VGIC GICv3 distributor, SPIs, SGI/PPI state, ICH_VMCR/APR and the
 *               exact active/pending lists.
 *
 * Every vCPU is frozen by the ioctl layer.  A restore decodes and validates
 * the complete image and checks it against the destination before changing
 * any state, so a refused image leaves the VM untouched.  Tracing state is
 * never part of these records: HyperTrace starts a fresh session after a
 * restore (see contrib/hypertrace/ARCH-SNAPSHOT.5BSD.md).
 */

#include "opt_bhyve_snapshot.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sx.h>

#include <machine/armreg.h>
#include <machine/vfp.h>
#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_snapshot_envelope.h>
#include <dev/vmm/vmm_vm.h>

#include "arm64.h"
#include "vmm_snapshot_arm64.h"
#include "io/vgic.h"
#include "io/vtimer.h"

#ifndef BHYVE_SNAPSHOT
#error "vmm_snapshot_machdep.c requires options BHYVE_SNAPSHOT"
#endif

static MALLOC_DEFINE(M_VMM_SNAPSHOT, "vmm_snapshot", "vmm checkpoint staging");

_Static_assert(sizeof(((struct vfpstate *)0)->vfp_regs) ==
    sizeof(((struct vmm_snapshot_arm64_fp *)0)->vregs),
    "FP/SIMD register file size");
_Static_assert(PSR_M_MASK == VMM_SNAPSHOT_ARM64_PSR_M_MASK &&
    PSR_M_32 == VMM_SNAPSHOT_ARM64_PSR_M_32 &&
    PSR_M_EL0t == VMM_SNAPSHOT_ARM64_PSR_M_EL0t &&
    PSR_M_EL1t == VMM_SNAPSHOT_ARM64_PSR_M_EL1t &&
    PSR_M_EL1h == VMM_SNAPSHOT_ARM64_PSR_M_EL1h, "portable PSTATE modes");
_Static_assert(PMCR_N_MASK == VMM_SNAPSHOT_ARM64_PMCR_N_MASK,
    "portable PMCR.N");

/* Wire register -> hypctx register.  PC is vcpu->nextpc, handled apart. */
static int
arm64_snapshot_hypctx_reg(u_int wire)
{

	if (wire < VMM_SNAPSHOT_ARM64_X30)
		return (GPR_X(wire - VMM_SNAPSHOT_ARM64_X0));
	if (wire >= VMM_SNAPSHOT_ARM64_PMEVCNTR0_EL0 &&
	    wire <= VMM_SNAPSHOT_ARM64_PMEVCNTR30_EL0)
		return (PMEVCNTR_EL0(wire - VMM_SNAPSHOT_ARM64_PMEVCNTR0_EL0));
	if (wire >= VMM_SNAPSHOT_ARM64_PMEVTYPER0_EL0 &&
	    wire <= VMM_SNAPSHOT_ARM64_PMEVTYPER30_EL0)
		return (PMEVTYPER_EL0(wire -
		    VMM_SNAPSHOT_ARM64_PMEVTYPER0_EL0));
	if (wire >= VMM_SNAPSHOT_ARM64_DBGBCR0_EL1 &&
	    wire <= VMM_SNAPSHOT_ARM64_DBGBCR15_EL1)
		return (DBGBCR_EL1(wire - VMM_SNAPSHOT_ARM64_DBGBCR0_EL1));
	if (wire >= VMM_SNAPSHOT_ARM64_DBGBVR0_EL1 &&
	    wire <= VMM_SNAPSHOT_ARM64_DBGBVR15_EL1)
		return (DBGBVR_EL1(wire - VMM_SNAPSHOT_ARM64_DBGBVR0_EL1));
	if (wire >= VMM_SNAPSHOT_ARM64_DBGWCR0_EL1 &&
	    wire <= VMM_SNAPSHOT_ARM64_DBGWCR15_EL1)
		return (DBGWCR_EL1(wire - VMM_SNAPSHOT_ARM64_DBGWCR0_EL1));
	if (wire >= VMM_SNAPSHOT_ARM64_DBGWVR0_EL1 &&
	    wire <= VMM_SNAPSHOT_ARM64_DBGWVR15_EL1)
		return (DBGWVR_EL1(wire - VMM_SNAPSHOT_ARM64_DBGWVR0_EL1));
	switch (wire) {
	case VMM_SNAPSHOT_ARM64_X30:		return (GPR_LR);
	case VMM_SNAPSHOT_ARM64_SP_EL0:		return (SP_EL0);
	case VMM_SNAPSHOT_ARM64_PSTATE:		return (HOST_SPSR_EL2);
	case VMM_SNAPSHOT_ARM64_SP_EL1:		return (HOST_SP_EL1);
	case VMM_SNAPSHOT_ARM64_ELR_EL1:	return (ELR_EL1);
	case VMM_SNAPSHOT_ARM64_SPSR_EL1:	return (SPSR_EL1);
	case VMM_SNAPSHOT_ARM64_SCTLR_EL1:	return (SCTLR_EL1);
	case VMM_SNAPSHOT_ARM64_TTBR0_EL1:	return (TTBR0_EL1);
	case VMM_SNAPSHOT_ARM64_TTBR1_EL1:	return (TTBR1_EL1);
	case VMM_SNAPSHOT_ARM64_TCR_EL1:	return (TCR_EL1);
	case VMM_SNAPSHOT_ARM64_MAIR_EL1:	return (MAIR_EL1);
	case VMM_SNAPSHOT_ARM64_AMAIR_EL1:	return (AMAIR_EL1);
	case VMM_SNAPSHOT_ARM64_ESR_EL1:	return (ESR_EL1);
	case VMM_SNAPSHOT_ARM64_FAR_EL1:	return (FAR_EL1);
	case VMM_SNAPSHOT_ARM64_AFSR0_EL1:	return (AFSR0_EL1);
	case VMM_SNAPSHOT_ARM64_AFSR1_EL1:	return (AFSR1_EL1);
	case VMM_SNAPSHOT_ARM64_VBAR_EL1:	return (VBAR_EL1);
	case VMM_SNAPSHOT_ARM64_CONTEXTIDR_EL1:	return (CONTEXTIDR_EL1);
	case VMM_SNAPSHOT_ARM64_CPACR_EL1:	return (CPACR_EL1);
	case VMM_SNAPSHOT_ARM64_ACTLR_EL1:	return (ACTLR_EL1);
	case VMM_SNAPSHOT_ARM64_PAR_EL1:	return (PAR_EL1);
	case VMM_SNAPSHOT_ARM64_CSSELR_EL1:	return (CSSELR_EL1);
	case VMM_SNAPSHOT_ARM64_MDSCR_EL1:	return (MDSCR_EL1);
	case VMM_SNAPSHOT_ARM64_MDCCINT_EL1:	return (MDCCINT_EL1);
	case VMM_SNAPSHOT_ARM64_TPIDR_EL0:	return (TPIDR_EL0);
	case VMM_SNAPSHOT_ARM64_TPIDRRO_EL0:	return (TPIDRRO_EL0);
	case VMM_SNAPSHOT_ARM64_TPIDR_EL1:	return (TPIDR_EL1);
	case VMM_SNAPSHOT_ARM64_DBGCLAIMSET_EL1: return (DBGCLAIMSET_EL1);
	case VMM_SNAPSHOT_ARM64_VMPIDR_EL2:	return (HOST_VMPIDR_EL2);
	case VMM_SNAPSHOT_ARM64_VPIDR_EL2:	return (HOST_VPIDR_EL2);
	case VMM_SNAPSHOT_ARM64_PMCR_EL0:	return (PMCR_EL0);
	case VMM_SNAPSHOT_ARM64_PMCCNTR_EL0:	return (PMCCNTR_EL0);
	case VMM_SNAPSHOT_ARM64_PMCCFILTR_EL0:	return (PMCCFILTR_EL0);
	case VMM_SNAPSHOT_ARM64_PMUSERENR_EL0:	return (PMUSERENR_EL0);
	case VMM_SNAPSHOT_ARM64_PMSELR_EL0:	return (PMSELR_EL0);
	case VMM_SNAPSHOT_ARM64_PMXEVCNTR_EL0:	return (PMXEVCNTR_EL0);
	case VMM_SNAPSHOT_ARM64_PMCNTENSET_EL0:	return (PMCNTENSET_EL0);
	case VMM_SNAPSHOT_ARM64_PMINTENSET_EL1:	return (PMINTENSET_EL1);
	case VMM_SNAPSHOT_ARM64_PMOVSSET_EL0:	return (PMOVSSET_EL0);
	default:
		return (-1);
	}
}

/*
 * ARM64 publishes no deferred event bits through the MI checkpoint
 * coordinator: vGIC injection does not use the coordinator ingress.  Any call
 * therefore indicates a broken coordinator invariant.
 */
void
vm_event_checkpoint_deferred_apply(void *arg, uint16_t vcpuid,
    uint64_t deferred_mask)
{

	panic("%s: unexpected deferred event %#jx for vCPU %u", __func__,
	    (uintmax_t)deferred_mask, vcpuid);
}

static int
arm64_snapshot_vcpus(struct vm *vm, uint32_t *instances, uint32_t *countp)
{
	struct vcpu *vcpu;
	uint32_t count;
	uint16_t maxcpus;

	maxcpus = vm_get_maxcpus(vm);
	count = 0;
	for (uint16_t i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
			return (EBUSY);
		instances[count++] = i;
	}
	if (count == 0)
		return (EINVAL);
	*countp = count;
	return (0);
}

static int
arm64_snapshot_vcpu_capture(struct vcpu *vcpu,
    struct vmm_snapshot_arm64_vcpu_stage *stage, uint64_t cntvoff)
{
	struct hypctx *hypctx;
	struct vfpstate *fpu;
	int reg;

	hypctx = vcpu->cookie;
	/* Debug-exit capabilities hold host-owned SPSR/MDSCR shadows. */
	if (hypctx->setcaps != 0)
		return (EBUSY);
	if (!vtimer_snapshot_supported(hypctx) ||
	    hypctx_read_sys_reg(hypctx, HOST_CNTVOFF_EL2) != cntvoff)
		return (EOPNOTSUPP);
	for (u_int i = 0; i < VMM_SNAPSHOT_ARM64_REG_COUNT; i++) {
		if (i == VMM_SNAPSHOT_ARM64_PC) {
			stage->vcpu.regs[i] = vcpu->nextpc;
			continue;
		}
		reg = arm64_snapshot_hypctx_reg(i);
		KASSERT(reg >= 0, ("%s: unmapped register %u", __func__, i));
		stage->vcpu.regs[i] = hypctx_read_sys_reg(hypctx, reg);
	}
	if (hypctx->has_exception)
		stage->vcpu.flags |= VMM_SNAPSHOT_ARM64_VCPU_F_EXCEPTION;
	if (hypctx->dbg_oslock)
		stage->vcpu.flags |= VMM_SNAPSHOT_ARM64_VCPU_F_OSLOCK;
	stage->common.flags = 0;
	stage->common.next_pc = vcpu->nextpc;
	fpu = vcpu->guestfpu;
	memcpy(stage->fp.vregs, fpu->vfp_regs, sizeof(stage->fp.vregs));
	stage->fp.fpcr = fpu->vfp_fpcr;
	stage->fp.fpsr = fpu->vfp_fpsr;
	vtimer_snapshot_capture(hypctx, &stage->timer);
	return (0);
}

static int
arm64_snapshot_vm_save(struct vm *vm, struct vm_snapshot_meta *meta,
    struct vmm_snapshot_arm64_vcpu_stage *stage, uint32_t *instances)
{
	struct vmm_snapshot_arm64_transaction transaction;
	struct hyp *hyp;
	uint8_t *wire;
	size_t length, written;
	uint32_t count;
	int error;

	hyp = vm_get_cookie(vm);
	error = arm64_snapshot_vcpus(vm, instances, &count);
	if (error != 0)
		return (error);
	memset(&transaction, 0, sizeof(transaction));
	transaction.vm.max_vcpus = vm_get_maxcpus(vm);
	transaction.vm.vcpu_count = count;
	transaction.vcpu_count = count;
	transaction.arm64.cntfrq = READ_SPECIALREG(cntfrq_el0);
	for (uint32_t i = 0; i < count; i++) {
		stage[i].instance = instances[i];
		error = arm64_snapshot_vcpu_capture(vm_vcpu(vm, instances[i]),
		    &stage[i], hyp->cntvoff_el2);
		if (error != 0)
			return (error);
	}
	/* Sample the counter after every timer value has been captured. */
	transaction.arm64.guest_count = READ_CNTPCT() - hyp->cntvoff_el2;
	error = vmm_snapshot_arm64_vm_size(count, &length);
	if (error != 0)
		return (error);
	if (length > meta->buffer.buf_rem)
		return (E2BIG);
	wire = malloc(length, M_VMM_SNAPSHOT, M_WAITOK | M_ZERO);
	error = vmm_snapshot_arm64_vm_encode(&transaction, stage, count, wire,
	    length, &written);
	if (error == 0)
		error = vm_snapshot_buf(wire, written, meta);
	explicit_bzero(wire, length);
	free(wire, M_VMM_SNAPSHOT);
	return (error);
}

static int
arm64_snapshot_vm_restore(struct vm *vm, struct vm_snapshot_meta *meta,
    struct vmm_snapshot_arm64_vcpu_stage *stage, uint32_t *instances)
{
	struct vmm_snapshot_arm64_transaction transaction;
	struct hypctx *hypctx;
	struct vcpu *vcpu;
	struct hyp *hyp;
	struct vfpstate *fpu;
	uint8_t *wire;
	size_t bound, length;
	uint64_t cntvoff;
	uint32_t count;
	uint16_t maxcpus;
	int error, reg;

	hyp = vm_get_cookie(vm);
	maxcpus = vm_get_maxcpus(vm);
	error = arm64_snapshot_vcpus(vm, instances, &count);
	if (error != 0)
		return (error);
	error = vmm_snapshot_arm64_vm_size(maxcpus, &bound);
	if (error != 0)
		return (error);
	length = meta->buffer.buf_rem;
	if (length > bound || length < VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE)
		return (EINVAL);
	/* Own the bytes before parsing them; userspace may still change them. */
	wire = malloc(length, M_VMM_SNAPSHOT, M_WAITOK | M_ZERO);
	error = vm_snapshot_buf(wire, length, meta);
	if (error == 0)
		error = vmm_snapshot_arm64_vm_decode(wire, length, stage,
		    maxcpus, &transaction);
	explicit_bzero(wire, length);
	free(wire, M_VMM_SNAPSHOT);
	if (error != 0)
		return (error);

	/* Destination checks.  Nothing has been modified yet. */
	if (transaction.vm.max_vcpus != maxcpus ||
	    transaction.vcpu_count != count ||
	    transaction.arm64.cntfrq != READ_SPECIALREG(cntfrq_el0))
		return (EINVAL);
	for (uint32_t i = 0; i < count; i++) {
		if (stage[i].instance != instances[i])
			return (EINVAL);
		hypctx = vm_vcpu(vm, instances[i])->cookie;
		if (hypctx->setcaps != 0)
			return (EBUSY);
		if (!vtimer_snapshot_supported(hypctx))
			return (EOPNOTSUPP);
		if (stage[i].vcpu.regs[VMM_SNAPSHOT_ARM64_VMPIDR_EL2] !=
		    hypctx_read_sys_reg(hypctx, HOST_VMPIDR_EL2) ||
		    stage[i].vcpu.regs[VMM_SNAPSHOT_ARM64_VPIDR_EL2] !=
		    hypctx_read_sys_reg(hypctx, HOST_VPIDR_EL2) ||
		    (stage[i].vcpu.regs[VMM_SNAPSHOT_ARM64_PMCR_EL0] &
		    PMCR_N_MASK) != (hypctx_read_sys_reg(hypctx, PMCR_EL0) &
		    PMCR_N_MASK))
			return (EINVAL);
	}

	/* Commit. */
	for (uint32_t i = 0; i < count; i++)
		vtimer_snapshot_quiesce(vm_vcpu(vm, instances[i])->cookie);
	cntvoff = READ_CNTPCT() - transaction.arm64.guest_count;
	hyp->cntvoff_el2 = cntvoff;
	for (uint32_t i = 0; i < count; i++) {
		vcpu = vm_vcpu(vm, instances[i]);
		hypctx = vcpu->cookie;
		for (u_int r = 0; r < VMM_SNAPSHOT_ARM64_REG_COUNT; r++) {
			/* Host-assigned identity is checked, never applied. */
			if (r == VMM_SNAPSHOT_ARM64_VMPIDR_EL2 ||
			    r == VMM_SNAPSHOT_ARM64_VPIDR_EL2)
				continue;
			if (r == VMM_SNAPSHOT_ARM64_PC)
				continue;
			reg = arm64_snapshot_hypctx_reg(r);
			hypctx_write_sys_reg(hypctx, reg, stage[i].vcpu.regs[r]);
		}
		vcpu->nextpc = stage[i].vcpu.regs[VMM_SNAPSHOT_ARM64_PC];
		hypctx_write_sys_reg(hypctx, HOST_ELR_EL2, vcpu->nextpc);
		hypctx->has_exception = (stage[i].vcpu.flags &
		    VMM_SNAPSHOT_ARM64_VCPU_F_EXCEPTION) != 0;
		hypctx->dbg_oslock = (stage[i].vcpu.flags &
		    VMM_SNAPSHOT_ARM64_VCPU_F_OSLOCK) != 0;
		fpu = vcpu->guestfpu;
		memcpy(fpu->vfp_regs, stage[i].fp.vregs, sizeof(fpu->vfp_regs));
		fpu->vfp_fpcr = stage[i].fp.fpcr;
		fpu->vfp_fpsr = stage[i].fp.fpsr;
		vtimer_snapshot_apply(hypctx, &stage[i].timer);
		hypctx_write_sys_reg(hypctx, HOST_CNTVOFF_EL2, cntvoff);
	}
	return (0);
}

static int
arm64_snapshot_vm(struct vm *vm, struct vm_snapshot_meta *meta)
{
	struct vmm_snapshot_arm64_vcpu_stage *stage;
	uint32_t *instances;
	uint16_t maxcpus;
	int error;

	maxcpus = vm_get_maxcpus(vm);
	if (maxcpus == 0 || maxcpus > VMM_SNAPSHOT_ARM64_MAX_VCPUS)
		return (EINVAL);
	stage = mallocarray(maxcpus, sizeof(*stage), M_VMM_SNAPSHOT,
	    M_WAITOK | M_ZERO);
	instances = mallocarray(maxcpus, sizeof(*instances), M_VMM_SNAPSHOT,
	    M_WAITOK | M_ZERO);
	if (meta->op == VM_SNAPSHOT_SAVE)
		error = arm64_snapshot_vm_save(vm, meta, stage, instances);
	else
		error = arm64_snapshot_vm_restore(vm, meta, stage, instances);
	explicit_bzero(stage, (size_t)maxcpus * sizeof(*stage));
	free(stage, M_VMM_SNAPSHOT);
	free(instances, M_VMM_SNAPSHOT);
	return (error);
}

static int
arm64_snapshot_vgic(struct vm *vm, struct vm_snapshot_meta *meta)
{
	struct vmm_snapshot_arm64_vgic_transaction *transaction;
	struct vmm_snapshot_arm64_vgic_stage *stage;
	struct hyp *hyp;
	uint8_t *wire;
	size_t bound, length, written;
	uint32_t *instances, count;
	uint16_t maxcpus;
	int error;

	hyp = vm_get_cookie(vm);
	maxcpus = vm_get_maxcpus(vm);
	if (maxcpus == 0 || maxcpus > VMM_SNAPSHOT_ARM64_MAX_VCPUS)
		return (EINVAL);
	instances = mallocarray(maxcpus, sizeof(*instances), M_VMM_SNAPSHOT,
	    M_WAITOK | M_ZERO);
	error = arm64_snapshot_vcpus(vm, instances, &count);
	free(instances, M_VMM_SNAPSHOT);
	if (error != 0)
		return (error);
	transaction = malloc(sizeof(*transaction), M_VMM_SNAPSHOT,
	    M_WAITOK | M_ZERO);
	stage = mallocarray(maxcpus, sizeof(*stage), M_VMM_SNAPSHOT,
	    M_WAITOK | M_ZERO);
	wire = NULL;
	length = 0;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = vgic_snapshot_capture(hyp, transaction, stage, maxcpus);
		if (error == 0)
			error = vmm_snapshot_arm64_vgic_size(
			    transaction->vcpu_count, &length);
		if (error == 0) {
			wire = malloc(length, M_VMM_SNAPSHOT, M_WAITOK | M_ZERO);
			error = vmm_snapshot_arm64_vgic_encode(transaction,
			    stage, transaction->vcpu_count, wire, length,
			    &written);
		}
		if (error == 0 && written > meta->buffer.buf_rem)
			error = E2BIG;
		if (error == 0)
			error = vm_snapshot_buf(wire, written, meta);
	} else {
		error = vmm_snapshot_arm64_vgic_size(maxcpus, &bound);
		length = meta->buffer.buf_rem;
		if (error == 0 && (length > bound ||
		    length < VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE))
			error = EINVAL;
		if (error == 0) {
			wire = malloc(length, M_VMM_SNAPSHOT, M_WAITOK | M_ZERO);
			error = vm_snapshot_buf(wire, length, meta);
		}
		if (error == 0)
			error = vmm_snapshot_arm64_vgic_decode(wire, length,
			    stage, maxcpus, transaction);
		if (error == 0) {
			/* Timer callouts must not race the list rebuild. */
			for (uint32_t i = 0; i < transaction->vcpu_count; i++) {
				struct vcpu *vcpu;

				vcpu = vm_vcpu(vm, stage[i].instance);
				if (vcpu == NULL) {
					error = EINVAL;
					break;
				}
			}
		}
		if (error == 0) {
			for (uint32_t i = 0; i < transaction->vcpu_count; i++)
				vtimer_snapshot_quiesce(
				    vm_vcpu(vm, stage[i].instance)->cookie);
			error = vgic_snapshot_restore(hyp, transaction, stage,
			    transaction->vcpu_count);
		}
	}
	if (wire != NULL) {
		explicit_bzero(wire, length);
		free(wire, M_VMM_SNAPSHOT);
	}
	explicit_bzero(stage, (size_t)maxcpus * sizeof(*stage));
	free(stage, M_VMM_SNAPSHOT);
	explicit_bzero(transaction, sizeof(*transaction));
	free(transaction, M_VMM_SNAPSHOT);
	return (error);
}

int
vm_snapshot_req(struct vm *vm, struct vm_snapshot_meta *meta)
{
	int error;

	if (vm == NULL || meta == NULL || !vm_snapshot_op_is_kernel(meta->op))
		return (EINVAL);
	switch (meta->dev_req) {
	case STRUCT_VM:
	case STRUCT_VGIC:
		break;
	default:
		return (EINVAL);
	}
	/* Revoke any dirty-log ticket before either save or restore. */
	vm_xlock_memsegs(vm);
	error = vm_mem_dirty_log_invalidate(vm);
	vm_unlock_memsegs(vm);
	KASSERT(error == 0 || error == EOVERFLOW,
	    ("%s: invalid dirty-log owner state %d", __func__, error));

	switch (meta->dev_req) {
	case STRUCT_VM:
		return (arm64_snapshot_vm(vm, meta));
	default:
		return (arm64_snapshot_vgic(vm, meta));
	}
}

/*
 * Consumes the one-shot restore-time credential (checked by the caller).
 * The counter offset was rebased when STRUCT_VM was restored; this re-arms
 * the software timer callouts against it now that all records are present.
 */
int
vm_restore_time(struct vm *vm)
{
	struct vcpu *vcpu;
	uint16_t maxcpus;

	maxcpus = vm_get_maxcpus(vm);
	for (uint16_t i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		vtimer_snapshot_rearm(vcpu->cookie);
	}
	return (0);
}
